"""The sandboxed workspace the Maker agent acts on.

Defence in depth: even if a human approves a held action, the executor itself
refuses network binaries, runs commands without a shell and with a scrubbed
environment, and "network" calls are recorded to a local outbox instead of
leaving the machine.
"""
from __future__ import annotations

import json
import os
import posixpath
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .ledger import sha256_hex
from .risk import NET_BINARIES, PRIV_BINARIES, rel_path

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv"}


class ToolError(Exception):
    pass


class Workspace:
    def __init__(self, root: str | os.PathLike, outbox: str | os.PathLike | None = None):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.outbox = Path(outbox) if outbox else self.root.parent / "outbox.jsonl"

    def safe(self, p: str) -> Path:
        rel = rel_path(self.root, p)
        if rel is None:
            raise ToolError(f"path '{p}' escapes the workspace")
        return self.root / rel

    def read_text(self, p: str, max_bytes: int = 200_000) -> str:
        path = self.safe(p)
        if not path.is_file():
            raise ToolError(f"no such file: {p}")
        return path.read_bytes()[:max_bytes].decode("utf-8", "replace")

    def read_bytes_or_none(self, p: str) -> bytes | None:
        path = self.safe(p)
        return path.read_bytes() if path.is_file() else None

    def write_text(self, p: str, content: str) -> dict:
        path = self.safe(p)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode("utf-8")
        path.write_bytes(data)
        return {"bytes": len(data), "sha256": sha256_hex(data)}

    def delete(self, p: str) -> None:
        path = self.safe(p)
        if path.is_file():
            path.unlink()

    def listing(self, max_files: int = 60) -> list[str]:
        out: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for f in sorted(filenames):
                out.append(Path(dirpath, f).relative_to(self.root).as_posix())
                if len(out) >= max_files:
                    return out
        return out

    def run(self, command: str, timeout: int = 30) -> dict:
        try:
            argv = shlex.split(command)
        except ValueError as e:
            raise ToolError(f"cannot parse command: {e}")
        if not argv:
            raise ToolError("empty command")
        exe = posixpath.basename(argv[0])
        if exe in NET_BINARIES or exe in PRIV_BINARIES:
            raise ToolError(f"sandbox: '{exe}' is disabled in this build")
        if exe == "pytest":
            argv = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *argv[1:]]
        elif exe in ("python", "python3"):
            argv = [sys.executable, *argv[1:]]
            if argv[1:3] == ["-m", "pytest"]:
                argv = argv[:3] + ["-p", "no:cacheprovider"] + argv[3:]
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1", "HOME": str(self.root)}
        try:
            r = subprocess.run(argv, cwd=self.root, env=env, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise ToolError(f"command timed out after {timeout}s")
        except FileNotFoundError:
            raise ToolError(f"command not found: {exe}")
        return {"exit": r.returncode, "stdout": r.stdout[-4000:], "stderr": r.stderr[-2000:]}

    def http_post(self, url: str, body: str) -> dict:
        """Simulated: recorded to a local outbox, never sent."""
        self.outbox.parent.mkdir(parents=True, exist_ok=True)
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "url": url, "bytes": len(body.encode())}
        with open(self.outbox, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        return {"status": "simulated", "note": "recorded to local outbox; nothing left this machine", **rec}
