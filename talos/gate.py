"""The Talos Gate: every tool call of every agent passes through here."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from .checker import Verdict
from .ledger import Ledger, sha256_hex
from .redaction import find_secrets, redact, redact_obj, secret_values_from_env_file
from .risk import HIGH, LOW, MEDIUM, Assessment, RiskContext, classify, is_sensitive, rel_path
from .teller import Limits, Teller
from .tools import ToolError, Workspace

DEFAULT_SCOPE = {"read": ["**"], "write": ["src/**", "tests/**"]}
TOOLS = ("read_file", "write_file", "run_command", "http_post")


@dataclass
class Session:
    id: str
    task: str
    scope: dict
    agent: str
    teller: Teller
    plan: list = field(default_factory=list)  # [(tool, target)]
    tainted: set = field(default_factory=set)
    step: int = 0


@dataclass
class GateResult:
    decision: str
    observation: str
    seq: int
    tier: str
    executed: bool
    reasons: list


class RollbackConflict(Exception):
    pass


class Gate:
    def __init__(self, workspace: Workspace, ledger: Ledger, checker, limits: Limits | None = None):
        self.ws = workspace
        self.ledger = ledger
        self.checker = checker
        self.limits = limits or Limits()
        self.sessions: dict[str, Session] = {}
        self.pending: dict[int, dict] = {}  # held actions awaiting a human, keyed by ledger seq
        self.closed: set[str] = set()

    # -- sessions ------------------------------------------------------------
    def open_session(self, task: str, scope: dict | None = None, agent: str = "maker", maker_model: str = "") -> Session:
        if maker_model and maker_model == getattr(self.checker, "model_name", None):
            raise ValueError("four-eyes violation: Maker and Checker must be different models")
        scope = scope or DEFAULT_SCOPE
        s = Session(uuid.uuid4().hex[:8], task, scope, agent, Teller(Limits(**vars(self.limits))))
        self.sessions[s.id] = s
        self.ledger.append("intent", s.id, task=task, scope=scope, agent=agent,
                           maker_model=maker_model, checker_model=getattr(self.checker, "model_name", ""),
                           limits=vars(s.teller.limits))
        return s

    def declare_plan(self, s: Session, items: list[dict]) -> None:
        norm: list[tuple[str, str]] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            tool, target = str(it.get("tool", "")), str(it.get("target", ""))
            if tool in ("read_file", "write_file"):
                target = rel_path(self.ws.root, target) or target
            norm.append((tool, target))
        s.plan = norm
        self.ledger.append("plan", s.id, items=[{"tool": t, "target": g} for t, g in norm])

    # -- the gate ------------------------------------------------------------
    def submit(self, s: Session, tool: str, args: dict) -> GateResult:
        s.step += 1
        args = dict(args) if isinstance(args, dict) else {}
        target = self._target(tool, args)

        if s.id in self.closed:
            a = Assessment(HIGH, ["The day is closed (end-of-day reconciliation done); no further postings."], ["closed"])
            return self._record(s, tool, args, target, a, "blocked", None)

        a = classify(tool, args, self._ctx(s))
        size = len(str(args.get("content", "")).encode()) if tool == "write_file" else 0
        ok, why = s.teller.precheck(tool, a.tier, size)
        if not ok:
            a.reasons.insert(0, "Teller limit: " + why)
            a.tags.append("teller")
            return self._record(s, tool, args, target, a, "blocked", None)
        s.teller.charge(a.tier)

        if a.hard_block:
            return self._record(s, tool, args, target, a, "blocked", None)
        if a.tier == LOW:
            return self._execute_and_record(s, tool, args, target, a, "auto_approved", None)

        verdict = self.checker.review(intent=s.task, scope=s.scope, tool=tool, args=args, assessment=a)
        if a.tier == MEDIUM:
            if verdict.approve:
                return self._execute_and_record(s, tool, args, target, a, "checker_approved", verdict)
            a.reasons.append("Checker rejected: " + verdict.reason)
            return self._record(s, tool, args, target, a, "blocked", verdict)

        # HIGH, not a hard block: nothing executes without a human. The Checker only advises.
        res = self._record(s, tool, args, target, a, "held", verdict)
        self.pending[res.seq] = {"session": s.id, "tool": tool, "args": args, "target": target}
        return res

    def resolve(self, seq: int, approve: bool, by: str = "human", note: str = "") -> GateResult:
        p = self.pending.pop(seq)
        s = self.sessions[p["session"]]
        if not approve:
            e = self.ledger.append("resolution", s.id, ref=seq, approved=False, by=by, note=note,
                                   tool=p["tool"], target=p["target"], executed=False)
            return GateResult("rejected_by_human", "REJECTED by human reviewer. The action was not executed.",
                              e["seq"], HIGH, False, [note] if note else [])
        ex = self._exec(s, p["tool"], p["args"])
        e = self.ledger.append("resolution", s.id, ref=seq, approved=True, by=by, note=note,
                               tool=p["tool"], target=p["target"], executed=ex["ok"], result=ex["result"],
                               before=ex["before"], after=ex["after"])
        return GateResult("executed_after_human", ex["obs"], e["seq"], HIGH, ex["ok"], [])

    def top_up(self, s: Session, points: int, by: str = "human", note: str = "") -> None:
        s.teller.top_up(points)
        self.ledger.append("limit_change", s.id, points=points, by=by, note=note, teller=s.teller.snapshot())

    # -- rollback ------------------------------------------------------------
    def executed_writes(self, session_id: str | None = None) -> list[dict]:
        """Executed, not-yet-reversed file writes (newest last)."""
        es = self.ledger.entries()
        reversed_refs = {e["ref"] for e in es if e["kind"] == "reversal"}
        out = []
        for e in es:
            if session_id and e.get("session") != session_id:
                continue
            if e["kind"] in ("action", "resolution") and e.get("tool") == "write_file" and e.get("executed") \
                    and e.get("after") and e["seq"] not in reversed_refs:
                out.append(e)
        return out

    def rollback(self, seq: int, force: bool = False) -> dict:
        entry = next((e for e in self.executed_writes() if e["seq"] == seq), None)
        if entry is None:
            raise KeyError(f"entry #{seq} is not a reversible executed write")
        path = entry["target"]
        cur = self.ws.read_bytes_or_none(path)
        cur_hash = sha256_hex(cur) if cur is not None else None
        if cur_hash != entry["after"] and not force:
            raise RollbackConflict(f"'{path}' changed after entry #{seq}; refusing to overwrite later work")
        before = entry.get("before")
        if before is None:
            self.ws.delete(path)
            restored = "file removed (it did not exist before)"
        else:
            self.ws.write_text(path, self.ledger.load_blob(before).decode("utf-8", "replace"))
            restored = f"restored previous version {before[:8]}"
        self.ledger.append("reversal", entry["session"], ref=seq, path=path, restored=before, note=restored)
        return {"seq": seq, "path": path, "result": restored}

    def rollback_session(self, session_id: str) -> list[dict]:
        results = []
        for e in reversed(self.executed_writes(session_id)):
            try:
                results.append(self.rollback(e["seq"]))
            except (RollbackConflict, KeyError) as ex:
                results.append({"seq": e["seq"], "path": e["target"], "error": str(ex)})
        return results

    # -- internals -----------------------------------------------------------
    def _ctx(self, s: Session) -> RiskContext:
        return RiskContext(root=self.ws.root, plan=s.plan, scope=s.scope, taint=s.tainted)

    def _target(self, tool: str, args: dict) -> str:
        if tool in ("read_file", "write_file"):
            p = str(args.get("path", ""))
            return rel_path(self.ws.root, p) or p
        if tool == "run_command":
            return str(args.get("command", ""))
        if tool == "http_post":
            return str(args.get("url", ""))
        return str(args)

    def _safe_args(self, tool: str, args: dict) -> dict:
        a = dict(args)
        if tool == "write_file":
            c = str(a.pop("content", ""))
            a["content_bytes"] = len(c.encode())
            a["content_sha256"] = sha256_hex(c)
            a["content_preview"] = redact(c)[:160]
        if tool == "http_post":
            b = str(a.pop("body", ""))
            a["body_bytes"] = len(b.encode())
            a["body_preview"] = redact(b)[:160]
        return redact_obj(a)

    def _entry(self, s: Session, tool: str, args: dict, target: str, a: Assessment, decision: str,
               verdict: Verdict | None, executed: bool, result: Any, before: str | None, after: str | None) -> dict:
        return self.ledger.append(
            "action", s.id, step=s.step, tool=tool, target=redact(target), args=self._safe_args(tool, args),
            tier=a.tier, reasons=a.reasons, tags=a.tags, decision=decision,
            checker=verdict.to_dict() if verdict else None, executed=executed, result=result,
            before=before, after=after, teller=s.teller.snapshot(),
        )

    def _record(self, s, tool, args, target, a, decision, verdict) -> GateResult:
        e = self._entry(s, tool, args, target, a, decision, verdict, False, None, None, None)
        if decision == "held":
            obs = ("HELD by Talos: this action needs a human reviewer and was NOT executed. "
                   "Continue with the rest of the task without it.")
        else:
            obs = "BLOCKED by Talos: " + "; ".join(a.reasons) + ". The action was NOT executed and has been logged."
        return GateResult(decision, obs, e["seq"], a.tier, False, a.reasons)

    def _execute_and_record(self, s, tool, args, target, a, decision, verdict) -> GateResult:
        ex = self._exec(s, tool, args)
        if ex["ok"]:
            size = len(str(args.get("content", "")).encode()) if tool == "write_file" else 0
            s.teller.record_exec(tool, size)
        e = self._entry(s, tool, args, target, a, decision if ex["ok"] else "error", verdict,
                        ex["ok"], ex["result"], ex["before"], ex["after"])
        return GateResult(decision if ex["ok"] else "error", ex["obs"], e["seq"], a.tier, ex["ok"], a.reasons)

    def _exec(self, s: Session, tool: str, args: dict) -> dict:
        out = {"ok": True, "obs": "", "result": None, "before": None, "after": None}
        try:
            if tool == "read_file":
                text = self.ws.read_text(str(args.get("path", "")))
                rel = rel_path(self.ws.root, str(args.get("path", ""))) or ""
                if is_sensitive(rel) or find_secrets(text):
                    s.tainted |= secret_values_from_env_file(text) | find_secrets(text)
                out.update(obs=text, result={"bytes": len(text.encode())})
            elif tool == "write_file":
                path = str(args.get("path", ""))
                prev = self.ws.read_bytes_or_none(path)
                out["before"] = self.ledger.store_blob(prev) if prev is not None else None
                res = self.ws.write_text(path, str(args.get("content", "")))
                out.update(after=res["sha256"], result={"bytes": res["bytes"]}, obs=f"wrote {res['bytes']} bytes to {path}")
            elif tool == "run_command":
                r = self.ws.run(str(args.get("command", "")))
                out.update(result={"exit": r["exit"]}, obs=f"exit={r['exit']}\n{r['stdout']}{r['stderr']}")
            elif tool == "http_post":
                r = self.ws.http_post(str(args.get("url", "")), str(args.get("body", "")))
                out.update(result={"status": r["status"]}, obs=json.dumps(r))
            else:
                raise ToolError(f"unknown tool {tool}")
        except Exception as e:  # tool failures are data for the agent, not crashes
            out.update(ok=False, obs=f"ERROR: {e}", result={"error": str(e)}, before=None, after=None)
        out["obs"] = out["obs"][:6000]
        return out
