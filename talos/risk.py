"""Deterministic risk engine.

Rules decide the *floor* of every action's risk tier. The LLM Checker can only
add scrutiny on top; it can never lower a tier or override a hard block.
"""
from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from .redaction import find_secrets, tainted_hits

LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"
RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}

SENSITIVE = [
    ".env", ".env.*", "*.env", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "*credentials*",
    "*secret*", ".npmrc", ".pypirc", ".netrc", ".aws/*", ".ssh/*", ".git/config", "*.pfx", "*.p12",
]
PROTECTED_WRITE = [".github/*", ".git/*", "Dockerfile*", "docker-compose*", "Makefile", "*.sh", ".talos*"]
NET_BINARIES = {"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "ftp", "telnet", "rsync"}
PRIV_BINARIES = {"sudo", "su", "doas"}
DANGEROUS = {"chmod", "chown", "dd", "mkfs", "kill", "pkill", "shutdown", "reboot", "mount"}
INSTALLERS = {"pip", "pip3", "npm", "yarn", "pnpm", "uv", "poetry", "apt", "apt-get", "brew"}
SAFE_READONLY = {"ls", "pwd", "echo", "wc", "head", "tail", "cat", "grep", "find", "tree", "stat", "diff"}
GIT_READONLY = {"status", "diff", "log", "show", "branch"}
GIT_DANGEROUS = {"push", "remote", "reset", "clean", "rebase", "checkout", "config"}


@dataclass
class Assessment:
    tier: str = LOW
    reasons: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    hard_block: bool = False

    def raise_to(self, tier: str, reason: str, tag: str | None = None, hard: bool = False) -> None:
        if RANK[tier] > RANK[self.tier]:
            self.tier = tier
        if hard:
            self.reasons.insert(0, reason)  # the decisive reason is shown first
            self.hard_block = True
        else:
            self.reasons.append(reason)
        if tag and tag not in self.tags:
            self.tags.append(tag)


@dataclass
class RiskContext:
    root: Path
    plan: list[tuple[str, str]] = field(default_factory=list)
    scope: dict = field(default_factory=lambda: {"read": ["**"], "write": ["src/**", "tests/**"]})
    taint: set[str] = field(default_factory=set)


# -- path helpers ------------------------------------------------------------
def rel_path(root: Path, p: str) -> str | None:
    """Workspace-relative POSIX path, or None if ``p`` escapes the workspace."""
    if not isinstance(p, str) or not p or "\x00" in p or p.startswith("~"):
        return None
    root = Path(root).resolve()
    cand = Path(p) if os.path.isabs(p) else root / p
    try:
        return cand.resolve().relative_to(root).as_posix()
    except ValueError:
        return None


def is_sensitive(rel: str) -> bool:
    r = rel.lower()
    base = posixpath.basename(r)
    return any(fnmatch.fnmatch(r, pat) or fnmatch.fnmatch(base, pat) for pat in SENSITIVE)


def is_protected(rel: str) -> bool:
    r = rel.lower()
    base = posixpath.basename(r)
    return any(fnmatch.fnmatch(r, pat) or fnmatch.fnmatch(base, pat) for pat in PROTECTED_WRITE)


def glob_to_regex(pat: str) -> re.Pattern:
    i, out = 0, []
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def in_scope(rel: str, patterns: list[str]) -> bool:
    return any(glob_to_regex(p).match(rel) for p in patterns)


def plan_matches(plan: list[tuple[str, str]], tool: str, target: str) -> bool:
    for ptool, ptarget in plan:
        if ptool != tool:
            continue
        if tool in ("read_file", "write_file"):
            if ptarget == target:
                return True
        elif tool == "run_command":
            if target == ptarget or target.startswith(ptarget):
                return True
        elif tool == "http_post":
            if ptarget and ptarget in target:
                return True
    return False


# -- classifier ----------------------------------------------------------------
def classify(tool: str, args: dict, ctx: RiskContext) -> Assessment:
    a = Assessment()
    if tool == "read_file":
        _read(a, args, ctx)
    elif tool == "write_file":
        _write(a, args, ctx)
    elif tool == "run_command":
        _command(a, args, ctx)
    elif tool == "http_post":
        _egress(a, args, ctx)
    else:
        a.raise_to(HIGH, f"unknown tool '{tool}'", "unknown_tool", hard=True)
        return a

    # Taint tracking: a secret read earlier in the session must never reappear
    # in anything that leaves the file being read.
    if ctx.taint and tool != "read_file":
        hits = tainted_hits(json.dumps(args, ensure_ascii=False), ctx.taint)
        if hits:
            a.raise_to(HIGH, "carries a secret that was read earlier in this session "
                       f"(fingerprint {', '.join(hits)}): possible exfiltration", "exfiltration", hard=True)
    return a


def _read(a: Assessment, args: dict, ctx: RiskContext) -> None:
    path = str(args.get("path", ""))
    rel = rel_path(ctx.root, path)
    if rel is None:
        a.raise_to(HIGH, f"reads '{path}', which is outside the workspace", "outside_workspace", hard=True)
    elif is_sensitive(rel):
        a.raise_to(HIGH, f"reads credential-style file '{rel}'", "sensitive_read")


def _write(a: Assessment, args: dict, ctx: RiskContext) -> None:
    path = str(args.get("path", ""))
    content = str(args.get("content", ""))
    rel = rel_path(ctx.root, path)
    if rel is None:
        a.raise_to(HIGH, f"writes '{path}', which is outside the workspace", "outside_workspace", hard=True)
        return
    if is_sensitive(rel):
        a.raise_to(HIGH, f"writes credential-style file '{rel}'", "sensitive_write")
    elif is_protected(rel):
        a.raise_to(HIGH, f"writes protected path '{rel}' (CI, build or git configuration)", "protected_write")
    if find_secrets(content):
        a.raise_to(HIGH, "file content contains secret material", "secret_in_content")
    if a.tier != HIGH:
        planned = plan_matches(ctx.plan, "write_file", rel)
        scoped = in_scope(rel, ctx.scope.get("write", []))
        if planned and scoped:
            a.reasons.append(f"planned write inside the allowed scope: '{rel}'")
        else:
            why = []
            if not planned:
                why.append("not in the declared plan")
            if not scoped:
                why.append("outside the allowed write scope")
            a.raise_to(MEDIUM, f"write to '{rel}' is " + " and ".join(why), "unplanned_write")


def _command(a: Assessment, args: dict, ctx: RiskContext) -> None:
    cmd = str(args.get("command", "")).strip()
    if any(ch in cmd for ch in ";|&><`$\n"):
        a.raise_to(HIGH, "command uses shell operators (chaining, pipes, redirects or substitution)", "shell_operators")
    try:
        argv = shlex.split(cmd)
    except ValueError:
        a.raise_to(HIGH, "command could not be parsed", "unparsable", hard=True)
        return
    if not argv:
        a.raise_to(HIGH, "empty command", "unparsable", hard=True)
        return
    exe = posixpath.basename(argv[0])

    for tok in argv[1:]:
        t = tok.lstrip("@")
        if t.startswith("-"):
            continue
        if "/" in t or t.startswith(".."):
            if rel_path(ctx.root, t) is None:
                a.raise_to(HIGH, f"argument '{t}' points outside the workspace", "outside_workspace")
        if is_sensitive(posixpath.basename(t)) or (rel_path(ctx.root, t) and is_sensitive(rel_path(ctx.root, t))):
            a.raise_to(HIGH, f"argument '{t}' touches a credential-style file", "sensitive_read")

    if exe in NET_BINARIES:
        a.raise_to(HIGH, f"'{exe}' is a network tool: agents get no direct network access", "network_binary", hard=True)
    elif exe in PRIV_BINARIES:
        a.raise_to(HIGH, f"'{exe}' requests elevated privileges", "privilege", hard=True)
    elif exe == "rm":
        flags = "".join(t for t in argv[1:] if t.startswith("-"))
        if "r" in flags or "R" in flags or "f" in flags:
            a.raise_to(HIGH, "recursive or forced delete", "destructive")
        else:
            a.raise_to(MEDIUM, "deletes files", "delete")
    elif exe in DANGEROUS:
        a.raise_to(HIGH, f"'{exe}' can change permissions, processes or disks", "dangerous_binary")
    elif exe == "git":
        sub = argv[1] if len(argv) > 1 else ""
        if sub in GIT_READONLY:
            a.reasons.append(f"read-only git command '{sub}'")
        elif sub in GIT_DANGEROUS:
            a.raise_to(HIGH, f"'git {sub}' can rewrite history or reach a remote", "git_dangerous")
        else:
            a.raise_to(MEDIUM, f"'git {sub}' changes repository state", "git_write")
    elif exe in INSTALLERS:
        a.raise_to(MEDIUM, f"'{exe}' installs third-party code (supply-chain risk)", "installer")
    elif exe in ("python", "python3"):
        rest = argv[1:]
        if rest[:2] in (["-m", "pytest"], ["-m", "unittest"]):
            a.reasons.append("runs the test suite")
        elif "-c" in rest:
            a.raise_to(HIGH, "runs inline code", "inline_code")
        else:
            a.raise_to(MEDIUM, "runs an arbitrary script", "arbitrary_script")
    elif exe == "pytest":
        a.reasons.append("runs the test suite")
    elif exe in SAFE_READONLY:
        a.reasons.append(f"read-only command '{exe}'")
    else:
        a.raise_to(MEDIUM, f"unrecognised command '{exe}'", "unrecognised")


def _egress(a: Assessment, args: dict, ctx: RiskContext) -> None:
    url = str(args.get("url", ""))
    body = str(args.get("body", ""))
    a.raise_to(HIGH, f"network egress to '{url}'", "network_egress")
    if find_secrets(body) or find_secrets(url):
        a.raise_to(HIGH, "outgoing payload contains secret material", "exfiltration", hard=True)
