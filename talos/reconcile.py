"""End-of-day reconciliation: three-way match of intent, plan and actual.

Like a bank closing its books, Talos checks that what the user *asked for*
(intent + allowed scope), what the agent *said it would do* (plan) and what
*actually happened* (ledger, then the disk itself) agree. Anything that does
not agree is posted to **suspense** until a human clears it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .gate import Gate, Session
from .ledger import Ledger, canonical, sha256_hex
from .risk import in_scope, plan_matches
from .tools import Workspace

SEV_ORDER = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
PREVENTED = "ATTEMPT_PREVENTED"
EXEC_TOOLS = ("write_file", "run_command", "http_post")


@dataclass
class Exc:
    code: str
    severity: str
    seq: int | None
    message: str
    cleared: bool = False

    @property
    def open(self) -> bool:
        return not self.cleared and self.severity in ("WARN", "CRITICAL") and self.code != PREVENTED

    def to_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity, "seq": self.seq,
                "message": self.message, "cleared": self.cleared}


@dataclass
class Report:
    session: str
    task: str
    scope: dict
    chain_ok: bool
    chain_msg: str
    counts: dict
    three_way: list[dict]
    exceptions: list[Exc]
    balanced: bool
    maker_model: str = ""
    checker_model: str = ""

    @property
    def open_exceptions(self) -> list[Exc]:
        return [e for e in self.exceptions if e.open]

    @property
    def prevented(self) -> list[Exc]:
        return [e for e in self.exceptions if e.code == PREVENTED]

    def to_dict(self) -> dict:
        return {"session": self.session, "task": self.task, "scope": self.scope, "chain_ok": self.chain_ok,
                "counts": self.counts, "three_way": self.three_way, "balanced": self.balanced,
                "exceptions": [e.to_dict() for e in self.exceptions]}

    def to_markdown(self) -> str:
        c = self.counts
        lines = [
            f"# Talos end-of-day report: session `{self.session}`",
            "",
            f"**Task:** {self.task}",
            f"**Maker:** `{self.maker_model or 'n/a'}`  |  **Checker:** `{self.checker_model or 'n/a'}`",
            "",
            f"## Verdict: {'BALANCED' if self.balanced else 'OUT OF BALANCE'}",
            f"- Ledger integrity: {'intact' if self.chain_ok else 'BROKEN. ' + self.chain_msg}",
            f"- Actions attempted: {c['attempted']}  (auto-approved {c['auto']}, checker-approved {c['checker']}, "
            f"human-approved {c['human']}, held/rejected {c['held']}, blocked {c['blocked']})",
            f"- Prevented attempts: {len(self.prevented)}",
            f"- Open suspense items: {len(self.open_exceptions)}",
            "",
            "## Three-way match (intent / plan / actual)",
            "| Item | Intent | Plan | Actual |",
            "|---|---|---|---|",
        ]
        for r in self.three_way:
            lines.append(f"| {r['item']} | {r['intent']} | {r['plan']} | {r['actual']} |")
        lines += ["", "## Exceptions"]
        if not self.exceptions:
            lines.append("None.")
        for e in sorted(self.exceptions, key=lambda x: (SEV_ORDER[x.severity], x.seq or 0)):
            ref = f"#{e.seq} " if e.seq else ""
            state = " (cleared)" if e.cleared else ""
            lines.append(f"- **{e.severity}** `{e.code}` {ref}{e.message}{state}")
        return "\n".join(lines) + "\n"


def reconcile(ledger: Ledger, session_id: str, ws: Workspace) -> Report:
    chain_ok, _, chain_msg = ledger.verify()
    es = [e for e in ledger.entries() if e.get("session") == session_id]
    intent = next(e for e in es if e["kind"] == "intent")
    scope = intent["scope"]
    plan_entries = [e for e in es if e["kind"] == "plan"]
    plan = [(p["tool"], p["target"]) for p in (plan_entries[-1]["items"] if plan_entries else [])]
    cleared = {e["ref"] for e in es if e["kind"] == "suspense_clear"}
    reversed_refs = {e["ref"] for e in es if e["kind"] == "reversal"}
    resolutions = {e["ref"]: e for e in es if e["kind"] == "resolution"}

    exceptions: list[Exc] = []
    counts = {"attempted": 0, "auto": 0, "checker": 0, "human": 0, "held": 0, "blocked": 0}
    postings: list[dict] = []  # everything that actually executed

    for e in es:
        if e["kind"] == "action":
            counts["attempted"] += 1
            d = e["decision"]
            if d == "auto_approved":
                counts["auto"] += 1
            elif d == "checker_approved":
                counts["checker"] += 1
            elif d == "blocked":
                counts["blocked"] += 1
            elif d == "held":
                counts["held"] += 1
            if e.get("executed"):
                postings.append({**e, "origin": e["seq"]})
            if d == "blocked":
                exceptions.append(Exc(PREVENTED, "CRITICAL" if "exfiltration" in e.get("tags", []) else "WARN", e["seq"],
                                      f"blocked {e['tool']} on `{e['target']}`: {e['reasons'][0] if e['reasons'] else ''}"))
            if d == "held":
                res = resolutions.get(e["seq"])
                if res is None:
                    exceptions.append(Exc("HELD_UNRESOLVED", "WARN", e["seq"],
                                          f"{e['tool']} on `{e['target']}` is still waiting for a human decision"))
                elif not res["approved"]:
                    who = ("auto-rejected at end of day (nobody approved it)" if res.get("by") == "eod-close"
                           else f"rejected by {res.get('by', 'human')}")
                    exceptions.append(Exc(PREVENTED, "WARN", e["seq"],
                                          f"{e['tool']} on `{e['target']}` was held and {who}"))
        elif e["kind"] == "resolution" and e.get("approved") and e.get("executed"):
            counts["human"] += 1
            postings.append({**e, "origin": e["ref"]})
            exceptions.append(Exc("HUMAN_OVERRIDE", "INFO", e["ref"],
                                  f"human approved high-risk {e['tool']} on `{e['target']}`", cleared=True))

    if any("teller" in e.get("tags", []) and e["kind"] == "action" for e in es):
        raised = any(e["kind"] == "limit_change" for e in es)
        exceptions.append(Exc("BUDGET_FROZEN", "WARN", None,
                              "the agent exhausted its teller limit and was frozen until a human raised it",
                              cleared=raised))

    # --- three-way match --------------------------------------------------------
    matched_plan: set[int] = set()
    three_way: list[dict] = []
    for p in postings:
        if p["tool"] not in EXEC_TOOLS and p["tool"] != "read_file":
            continue
        tool, target = p["tool"], p["target"]
        planned = plan_matches(plan, tool, target)
        if planned:
            for i, (pt, pg) in enumerate(plan):
                if pt == tool and plan_matches([(pt, pg)], tool, target):
                    matched_plan.add(i)
        if tool == "write_file":
            ok_scope = in_scope(target, scope.get("write", []))
        elif tool == "read_file":
            ok_scope = in_scope(target, scope.get("read", []))
        else:
            ok_scope = True
        is_cleared = p["origin"] in cleared or p["seq"] in reversed_refs or p.get("origin") in reversed_refs
        if tool in EXEC_TOOLS and not planned:
            exceptions.append(Exc("UNPLANNED_ACTION", "WARN", p["origin"],
                                  f"{tool} on `{target}` was executed but was not in the agent's declared plan",
                                  cleared=is_cleared))
        if not ok_scope:
            exceptions.append(Exc("OUT_OF_SCOPE", "WARN", p["origin"],
                                  f"{tool} on `{target}` is outside the scope the user allowed", cleared=is_cleared))
        if tool != "read_file":
            three_way.append({
                "item": f"{tool} `{target}`",
                "intent": "in scope" if ok_scope else "OUTSIDE scope",
                "plan": "planned" if planned else "UNPLANNED",
                "actual": f"executed (#{p['origin']})" + (" then rolled back" if p["seq"] in reversed_refs else ""),
            })
    for i, (pt, pg) in enumerate(plan):
        if i not in matched_plan and pt != "read_file":
            three_way.append({"item": f"{pt} `{pg}`", "intent": "in scope", "plan": "planned", "actual": "not executed"})
            exceptions.append(Exc("UNFULFILLED_PLAN", "INFO", None, f"planned {pt} on `{pg}` never happened"))

    # --- drift: replay expected file state, compare with the real disk ----------
    expected: dict[str, str | None] = {}
    for e in es:
        if e["kind"] in ("action", "resolution") and e.get("tool") == "write_file" and e.get("executed") and e.get("after"):
            expected[e["target"]] = e["after"]
        elif e["kind"] == "reversal":
            expected[e["path"]] = e.get("restored")
    for path, want in expected.items():
        cur = ws.read_bytes_or_none(path)
        got = sha256_hex(cur) if cur is not None else None
        if got != want:
            exceptions.append(Exc("DRIFT", "CRITICAL", None,
                                  f"`{path}` on disk does not match the ledger: it was changed outside Talos "
                                  f"(expected {str(want)[:8]}, found {str(got)[:8]})",
                                  cleared=("drift:" + path) in {str(e.get("note")) for e in es if e["kind"] == "suspense_clear"}))
    if not chain_ok:
        exceptions.append(Exc("CHAIN_BROKEN", "CRITICAL", None, "ledger integrity check failed: " + chain_msg))

    balanced = chain_ok and not any(x.open for x in exceptions)
    return Report(session_id, intent["task"], scope, chain_ok, chain_msg, counts, three_way, exceptions, balanced,
                  intent.get("maker_model", ""), intent.get("checker_model", ""))


def clear_suspense(gate: Gate, session_id: str, seq: int, note: str, by: str = "human") -> None:
    gate.ledger.append("suspense_clear", session_id, ref=seq, note=note, by=by)


def close_day(gate: Gate, s: Session) -> Report:
    """Reject anything still waiting for a human, reconcile, and seal the session."""
    for seq in [q for q, p in gate.pending.items() if p["session"] == s.id]:
        gate.resolve(seq, approve=False, by="eod-close", note="unresolved at end of day: auto-rejected")
    report = reconcile(gate.ledger, s.id, gate.ws)
    gate.ledger.append("eod", s.id, balanced=report.balanced, open_exceptions=len(report.open_exceptions),
                       prevented=len(report.prevented), report_sha256=sha256_hex(canonical(report.to_dict())))
    gate.closed.add(s.id)
    return report
