"""Plain-language views of the ledger: what was stopped, and a step-by-step story.

Used by the dashboard's Overview and Replay tabs. Pure functions over ledger
entries, so they are easy to test and can run anywhere.
"""
from __future__ import annotations

THREATS: list[tuple[str, str, set[str]]] = [
    ("Secret exfiltration", "Attempts to send credentials or secret-bearing data out of the machine.",
     {"exfiltration", "secret_in_content", "network_egress", "network_binary"}),
    ("Credential access", "Reads or writes of .env files, keys and other credential-style files.",
     {"sensitive_read", "sensitive_write"}),
    ("Sandbox escape", "Paths or arguments pointing outside the project workspace.",
     {"outside_workspace"}),
    ("Destructive or privileged commands", "Recursive deletes, history rewrites, sudo, permission changes.",
     {"destructive", "delete", "dangerous_binary", "git_dangerous", "privilege"}),
    ("Supply chain and arbitrary code", "Installers, inline code, shell chaining and unknown programs.",
     {"installer", "inline_code", "arbitrary_script", "unrecognised", "shell_operators", "unparsable"}),
    ("Scope creep", "Writes that were unplanned, protected (CI, build config) or used unknown tools.",
     {"unplanned_write", "protected_write", "unknown_tool"}),
    ("Runaway behaviour", "Actions refused because the agent's risk budget or limits were exhausted.",
     {"teller", "closed"}),
]


def stopped_actions(entries: list[dict]) -> list[dict]:
    """Actions that did NOT execute: blocked, or held and later rejected / auto-rejected / still waiting."""
    resolved = {e["ref"]: e for e in entries if e["kind"] == "resolution"}
    out = []
    for e in entries:
        if e["kind"] != "action":
            continue
        if e["decision"] == "blocked":
            out.append(e)
        elif e["decision"] == "held":
            res = resolved.get(e["seq"])
            if res is None or not res.get("approved"):
                out.append(e)
    return out


def threats_stopped(entries: list[dict]) -> list[dict]:
    """Group stopped actions into threat categories. Each action counts once, under its first matching category."""
    buckets = {name: {"name": name, "blurb": blurb, "count": 0, "examples": []} for name, blurb, _ in THREATS}
    other = {"name": "Other policy blocks", "blurb": "Blocked by the Checker or another rule.", "count": 0, "examples": []}
    for e in stopped_actions(entries):
        tags = set(e.get("tags", []))
        target = next((b for (name, _, tg) in THREATS if tags & tg for b in [buckets[name]]), other)
        target["count"] += 1
        if len(target["examples"]) < 3:
            target["examples"].append(f"#{e['seq']} {e['tool']} {e['target'][:48]}")
    rows = [b for b in buckets.values() if b["count"]]
    if other["count"]:
        rows.append(other)
    return sorted(rows, key=lambda r: -r["count"])


def narrate(e: dict) -> dict:
    """One ledger entry as a sentence. Returns {title, detail, tone} with tone in ok/info/warn/bad/mute."""
    k = e["kind"]
    if k == "intent":
        return {"title": "The task is set", "detail": e.get("task", ""), "tone": "info"}
    if k == "plan":
        return {"title": "Maker declares its plan", "detail": f"{len(e.get('items', []))} planned steps", "tone": "info"}
    if k == "action":
        what = f"{e['tool']} {e['target'][:60]}"
        why = e["reasons"][0] if e.get("reasons") else ""
        ck = e.get("checker")
        d = e["decision"]
        if d == "auto_approved":
            return {"title": f"Allowed: {what}", "detail": "Low risk, executed without review.", "tone": "ok"}
        if d == "checker_approved":
            return {"title": f"Checker approved: {what}",
                    "detail": (ck or {}).get("reason", "Independent model reviewed and agreed."), "tone": "info"}
        if d == "held":
            extra = f" Checker advises {ck['verdict']}." if ck else ""
            return {"title": f"Held for a human: {what}", "detail": why + extra, "tone": "warn"}
        if d == "blocked":
            return {"title": f"Blocked: {what}", "detail": why, "tone": "bad"}
        return {"title": f"Error: {what}", "detail": str((e.get("result") or {}).get("error", "")), "tone": "mute"}
    if k == "resolution":
        if e.get("approved"):
            return {"title": f"Human approved #{e['ref']}", "detail": f"{e['tool']} {e['target'][:60]} executed.", "tone": "info"}
        who = "End of day auto-rejected" if e.get("by") == "eod-close" else "Human rejected"
        return {"title": f"{who} #{e['ref']}", "detail": f"{e['tool']} {e['target'][:60]} did not run.", "tone": "warn"}
    if k == "limit_change":
        return {"title": "Limit raised by a human", "detail": f"+{e.get('points')} points by {e.get('by')}", "tone": "info"}
    if k == "suspense_clear":
        return {"title": f"Suspense item #{e.get('ref')} cleared", "detail": e.get("note", ""), "tone": "info"}
    if k == "reversal":
        return {"title": f"Rolled back #{e.get('ref')}", "detail": e.get("note", ""), "tone": "info"}
    if k == "eod":
        return {"title": "Day closed", "detail": "Balanced." if e.get("balanced") else
                f"Out of balance, {e.get('open_exceptions')} item(s) in suspense.", "tone": "ok" if e.get("balanced") else "bad"}
    return {"title": k, "detail": "", "tone": "mute"}


def replay_state(entries: list[dict], upto: int) -> dict:
    """Running totals after the first `upto` entries (1-based count)."""
    es = entries[:upto]
    used = budget = 0
    for e in es:
        if e["kind"] == "action" and e.get("teller"):
            used, budget = e["teller"]["used"], e["teller"]["budget"]
        if e["kind"] == "intent" and not budget:
            budget = (e.get("limits") or {}).get("risk_budget", 0)
        if e["kind"] == "limit_change" and e.get("teller"):
            used, budget = e["teller"]["used"], e["teller"]["budget"]
    stopped = stopped_actions(es)
    files = sorted({e["target"] for e in es
                    if e["kind"] in ("action", "resolution") and e.get("tool") == "write_file" and e.get("executed")})
    sens = [e for e in es if e["kind"] == "action" and "sensitive_read" in e.get("tags", [])]
    approved = {e["ref"] for e in es if e["kind"] == "resolution" and e.get("approved") and e.get("executed")}
    read = any(e.get("executed") or e["seq"] in approved for e in sens)
    return {"used": used, "budget": budget, "stopped": len(stopped), "files_changed": files,
            "secret_attempted": bool(sens), "secret_read": read}
