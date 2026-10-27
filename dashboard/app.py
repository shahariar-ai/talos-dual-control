"""Talos dashboard.  Run with:  streamlit run dashboard/app.py"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))

import theme  # noqa: E402
from talos.authority import LEVELS  # noqa: E402
from talos.certificate import build_certificate, render_html, verify_certificate  # noqa: E402
from talos.demo import SCENARIOS, restore, run_scenario, tamper  # noqa: E402
from talos.gate import RollbackConflict  # noqa: E402
from talos.insight import narrate, replay_state, threats_stopped  # noqa: E402
from talos.llm import DEFAULT_CHECKER_MODEL, DEFAULT_MAKER_MODEL  # noqa: E402
from talos.reconcile import clear_suspense, close_day, reconcile  # noqa: E402

DATA = Path(os.environ.get("TALOS_DATA", "./talos_data")).resolve()
TIER_COLOR, DECISION_COLOR = theme.TIER_COLOR, theme.DECISION_COLOR

st.set_page_config(page_title="Talos: dual control for AI agents", page_icon="🛡️", layout="wide")
st.html(theme.CSS)


def style_cell(v: str, table: dict) -> str:
    c = table.get(v)
    if not c:
        return ""
    r, g, b = (int(c[i:i + 2], 16) for i in (1, 3, 5))
    return f"color: {c}; background-color: rgba({r},{g},{b},0.16); font-weight: 700"


def ledger_frame(entries: list[dict]) -> pd.DataFrame:
    rows = []
    for e in entries:
        k = e["kind"]
        if k == "action":
            ck = e.get("checker")
            rows.append({"#": e["seq"], "time": e["ts"][11:19], "kind": "action", "tool": e["tool"],
                         "target": e["target"][:70], "tier": e["tier"], "decision": e["decision"],
                         "checker": (f"{ck['verdict']}: {ck['reason']}" if ck else ""),
                         "why": (e["reasons"][0] if e["reasons"] else "")})
        elif k == "resolution":
            rows.append({"#": e["seq"], "time": e["ts"][11:19], "kind": "resolution", "tool": e["tool"],
                         "target": e["target"][:70], "tier": "", "decision": "approved" if e["approved"] else "rejected",
                         "checker": "", "why": f"by {e['by']} (re #{e['ref']}) {e.get('note', '')}"})
        else:
            detail = {"intent": e.get("task", ""), "plan": f"{len(e.get('items', []))} planned steps",
                      "reversal": f"rolled back #{e.get('ref')}: {e.get('note', '')}",
                      "suspense_clear": f"cleared #{e.get('ref')}: {e.get('note', '')}",
                      "limit_change": f"limit +{e.get('points')} by {e.get('by')}",
                      "eod": f"day closed, balanced={e.get('balanced')}"}.get(k, "")
            rows.append({"#": e["seq"], "time": e["ts"][11:19], "kind": k, "tool": "", "target": "",
                         "tier": "", "decision": "", "checker": "", "why": detail[:110]})
    return pd.DataFrame(rows)[["#", "time", "kind", "tool", "target", "tier", "decision", "why", "checker"]]


def styled(df: pd.DataFrame):
    sty = df.style
    fn = sty.map if hasattr(sty, "map") else sty.applymap
    sty = fn(lambda v: style_cell(v, TIER_COLOR), subset=["tier"])
    fn = sty.map if hasattr(sty, "map") else sty.applymap
    return fn(lambda v: style_cell(v, DECISION_COLOR), subset=["decision"])


# ------------------------------------------------------------------ sidebar
st.sidebar.markdown("### 🛡️ TALOS")
st.sidebar.caption("Dual control for AI agents. Banking's oldest safety rules, for coding agents.")
api_key = os.environ.get("NEBIUS_API_KEY") or st.sidebar.text_input("Nebius API key (optional)", type="password")
live = st.sidebar.toggle("Live: Nemotron on Nebius Token Factory", value=False, disabled=not api_key,
                         help="Off = deterministic offline simulation (no API key, no network).")
scenario = st.sidebar.selectbox("Scenario", list(SCENARIOS), format_func=lambda k: SCENARIOS[k][0])
authority = st.sidebar.select_slider("Agent authority", options=list(LEVELS), value="standard",
                                     format_func=lambda k: LEVELS[k]["label"],
                                     help="Like a bank's delegated authority: a trainee gets a small cash limit.")
_lim = LEVELS[authority]["limits"]
st.sidebar.caption(f"{LEVELS[authority]['blurb']}  \nBudget {_lim.risk_budget} pts · {_lim.max_writes} writes · {_lim.max_commands} commands")
maker_model = st.sidebar.text_input("Maker model", os.environ.get("TALOS_MAKER_MODEL", DEFAULT_MAKER_MODEL), disabled=not live)
checker_model = st.sidebar.text_input("Checker model", os.environ.get("TALOS_CHECKER_MODEL", DEFAULT_CHECKER_MODEL), disabled=not live)
hardened = st.sidebar.checkbox("Harden Maker prompt against injection", value=False, disabled=not live,
                               help="Off shows Talos catching an agent that obeys the poisoned README.")
if st.sidebar.button("Run scenario", type="primary", width="stretch"):
    with st.spinner("Agent is working. Every tool call passes through Talos..."):
        try:
            st.session_state.run = run_scenario(DATA, scenario, live=live, maker_model=maker_model,
                                                checker_model=checker_model, api_key=api_key or None, hardened=hardened,
                                                authority=authority)
            st.session_state.anchor = None
        except Exception as e:  # missing key, bad model id, network...
            st.session_state.pop("run", None)
            st.sidebar.error(f"{type(e).__name__}: {e}")
st.sidebar.caption("Mode: " + ("LIVE (real Nemotron models)" if live else "OFFLINE SIMULATION (scripted agent)"))

run = st.session_state.get("run")
if run is None:
    st.html(theme.hero(live=live, intact=None))
    st.html('<h3 style="margin:6px 0 4px">How one action travels through Talos</h3>' + theme.flow())
    st.html('<h3 style="margin:22px 0 8px">The bank controls we ported</h3>' + theme.control_cards())
    st.info("Pick a scenario in the sidebar and press **Run scenario**. Offline simulation needs no API key.")
    st.stop()

gate, session = run.gate, run.session
ledger = gate.ledger
entries = ledger.entries()
actions = [e for e in entries if e["kind"] == "action"]
ok, bad, msg = ledger.verify(st.session_state.get("anchor"))
closed = session.id in gate.closed

st.html(theme.hero(live=run.mode == "live", intact=ok,
                   extra=theme.pill("Day closed" if closed else "Day open", "info")))

c = st.columns(6)
c[0].metric("Actions", len(actions))
c[1].metric("Auto-approved", sum(a["decision"] == "auto_approved" for a in actions))
c[2].metric("Checker-approved", sum(a["decision"] == "checker_approved" for a in actions))
c[3].metric("Held for human", len(gate.pending))
c[4].metric("Blocked", sum(a["decision"] == "blocked" for a in actions))
c[5].metric("Ledger", "intact" if ok else "BROKEN")
st.caption(f"Task: {session.task}   |   Maker: `{run.maker_llm.name}`   |   Checker: `{gate.checker.model_name}`")

t_over, t_ledger, t_held, t_teller, t_replay, t_eod, t_roll, t_integ = st.tabs(
    ["Overview", "Ledger", "Held for human", "Teller limits", "Replay", "End of day", "Rollback", "Integrity"])

# ------------------------------------------------------------------ overview
with t_over:
    left, right = st.columns([3, 2], gap="large")
    with left:
        snap0 = session.teller.snapshot()
        st.html('<h4 style="margin:0 0 6px">Risk budget burned, action by action</h4>')
        st.html(theme.gauge(snap0["used"], snap0["budget"], snap0["frozen"]))
        st.html(theme.timeline_svg(actions, snap0["budget"]))
    with right:
        stopped = threats_stopped(entries)
        total = sum(r["count"] for r in stopped)
        st.html(f'<h4 style="margin:0 0 8px">Threats stopped before they ran: '
                f'<span style="color:{theme.PALETTE["bad"]}">{total}</span></h4>' + theme.threat_cards(stopped))

# ------------------------------------------------------------------ ledger
with t_ledger:
    df = ledger_frame(entries)
    st.dataframe(styled(df), width="stretch", hide_index=True, column_config={
        "#": st.column_config.NumberColumn(width="small"), "time": st.column_config.TextColumn(width="small"),
        "target": st.column_config.TextColumn(width="medium"),
        "checker": st.column_config.TextColumn(width="large"), "why": st.column_config.TextColumn(width="large")})
    pick = st.selectbox("Inspect entry", [e["seq"] for e in entries], index=len(entries) - 1)
    st.json(entries[pick - 1])

# ------------------------------------------------------------------ held
with t_held:
    if not gate.pending:
        st.success("Nothing is waiting for a human.")
    for seq, p in list(gate.pending.items()):
        e = entries[seq - 1]
        with st.container(border=True):
            st.markdown(f"**#{seq}  {p['tool']}** on `{e['target']}`  :red[HIGH]")
            for r in e["reasons"]:
                st.write("- " + r)
            ck = e.get("checker")
            if ck:
                st.caption(f"Checker ({ck['model']}) advises **{ck['verdict']}**: {ck['reason']}")
            a, b, _ = st.columns([1, 1, 4])
            if a.button("Approve and execute", key=f"ap{seq}"):
                gate.resolve(seq, True, by="reviewer")
                st.rerun()
            if b.button("Reject", key=f"rj{seq}"):
                gate.resolve(seq, False, by="reviewer")
                st.rerun()

# ------------------------------------------------------------------ teller
with t_teller:
    snap = session.teller.snapshot()
    st.progress(min(snap["used"] / snap["budget"], 1.0), text=f"Risk budget: {snap['used']} / {snap['budget']} points")
    if snap["frozen"]:
        st.error("This agent is FROZEN: " + session.teller.freeze_reason)
    m = st.columns(4)
    m[0].metric("Files written", f"{snap['writes']} / {snap['max_writes']}")
    m[1].metric("Commands run", f"{snap['commands']} / {snap['max_commands']}")
    m[2].metric("Bytes written", f"{snap['bytes']} / {snap['max_bytes']}")
    m[3].metric("Network calls executed", snap["network"])
    st.caption("Costs: LOW 1, MEDIUM 5, HIGH 20 points. Blocked attempts are charged too, so a misbehaving agent burns its own limit.")
    if st.button("Raise limit by 40 points (human override)"):
        gate.top_up(session, 40, by="reviewer", note="manual top-up from dashboard")
        st.rerun()
    if run.mode == "live":
        st.subheader("Model usage (credits)")
        u = [x.usage for x in (run.maker_llm, run.checker_llm) if x is not None and hasattr(x, "usage")]
        st.dataframe(pd.DataFrame(u), hide_index=True, width="stretch")
        st.caption("The big Checker model is only called for MEDIUM and HIGH actions; LOW actions never reach it.")

# ------------------------------------------------------------------ replay
with t_replay:
    st.write("Scrub through the session like a flight recorder. Later steps are dimmed until you reach them.")
    step = st.slider("Step", 1, len(entries), len(entries), key="replay_step")
    rs = replay_state(entries, step)
    a, b = st.columns([2, 3], gap="large")
    with a:
        st.html(theme.gauge(rs["used"], rs["budget"]))
        m1, m2 = st.columns(2)
        m1.metric("Stopped so far", rs["stopped"])
        m2.metric("Files changed", len(rs["files_changed"]))
        st.html(theme.pill("A credential file was read", "bad") if rs["secret_read"]
                else theme.pill("Credential read attempted and stopped", "warn") if rs["secret_attempted"]
                else theme.pill("No credential file touched", "ok"))
        if rs["files_changed"]:
            st.caption("Changed so far: " + ", ".join(f"`{f}`" for f in rs["files_changed"]))
    with b:
        st.html(theme.story([(narrate(e), i < step) for i, e in enumerate(entries)]))

# ------------------------------------------------------------------ end of day
with t_eod:
    if not closed:
        st.write("Closing the day rejects anything still waiting for a human, then reconciles intent, plan and actual.")
        if st.button("Close the day and reconcile", type="primary"):
            close_day(gate, session)
            st.rerun()
    else:
        rep = reconcile(ledger, session.id, gate.ws)
        if rep.balanced:
            st.success(f"BALANCED. {len(rep.prevented)} attempts were prevented. Ledger intact.")
        else:
            st.error(f"OUT OF BALANCE. {len(rep.open_exceptions)} item(s) are in suspense until a human clears them.")
        st.subheader("Three-way match")
        st.dataframe(pd.DataFrame(rep.three_way), hide_index=True, width="stretch")
        st.subheader("Exceptions")
        for x in sorted(rep.exceptions, key=lambda z: (z.severity, z.seq or 0)):
            color = {"CRITICAL": "red", "WARN": "orange", "INFO": "gray"}[x.severity]
            ref = f"#{x.seq} " if x.seq else ""
            st.markdown(f":{color}[**{x.severity}**] `{x.code}` {ref}{x.message}" + ("  _(cleared)_" if x.cleared else ""))
            if x.open and x.seq and x.code in ("UNPLANNED_ACTION", "OUT_OF_SCOPE"):
                if st.button(f"Clear #{x.seq} ({x.code})", key=f"cl{x.code}{x.seq}"):
                    clear_suspense(gate, session.id, x.seq, "reviewed and accepted from dashboard", by="reviewer")
                    st.rerun()
        d1, d2 = st.columns(2)
        d1.download_button("Download report (Markdown)", rep.to_markdown(), file_name=f"talos-eod-{session.id}.md",
                           width="stretch")
        cert = build_certificate(ledger, session.id, rep)
        d2.download_button("Download day-close certificate (HTML)", render_html(cert),
                           file_name=f"talos-certificate-{session.id}.html", mime="text/html", type="primary",
                           width="stretch")
        cok, cmsg = verify_certificate(cert, ledger)
        (st.success if cok else st.error)(f"Certificate check: {cmsg}")
        st.caption(f"Seal `{cert['seal'][:24]}...` anchored at ledger entry #{cert['anchor']['seq']}. "
                   "Anyone holding the ledger can verify it with `python -m talos verify-cert`.")

# ------------------------------------------------------------------ rollback
with t_roll:
    writes = gate.executed_writes(session.id)
    if not writes:
        st.info("No agent writes to roll back.")
    for w in writes:
        a, b = st.columns([5, 1])
        a.markdown(f"**#{w['seq']}** wrote `{w['target']}` ({'new file' if w.get('before') is None else 'modified'})")
        if b.button("Roll back", key=f"rb{w['seq']}"):
            try:
                gate.rollback(w["seq"])
            except RollbackConflict as ex:
                st.warning(str(ex))
            else:
                st.rerun()
    if writes and st.button("Roll back everything this agent did", type="primary"):
        gate.rollback_session(session.id)
        st.rerun()

# ------------------------------------------------------------------ integrity
with t_integ:
    head = ledger.head()
    (st.success if ok else st.error)(("Chain intact. " if ok else "Chain BROKEN. ") + msg)
    st.code(f"head: #{head['seq']}  {head['hash']}", language="text")
    st.caption("A hash chain cannot show that the newest entries were deleted. Store the head hash somewhere Talos "
               "cannot write (a git commit, an email) and verify against it later.")
    if st.button("Take anchor now"):
        st.session_state.anchor = head
        st.rerun()
    st.divider()
    st.write("Try to cover your tracks: rewrite a blocked or held entry so it looks harmless.")
    targets = [a["seq"] for a in actions if a["decision"] in ("blocked", "held")]
    if targets:
        seq = st.selectbox("Entry to falsify", targets)
        a, b = st.columns(2)
        if a.button("Falsify this entry"):
            tamper(ledger, seq)
            st.rerun()
        if b.button("Restore original ledger"):
            restore(ledger)
            st.rerun()
