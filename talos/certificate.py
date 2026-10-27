"""Day-close certificate: a printable, tamper-evident receipt for one agent session.

Like the stamped slip a bank gives you, it states what happened and carries a seal.
The seal is a SHA-256 over the certificate body. The body also names the ledger
entry (number and hash) that closed the day, so anyone holding the ledger file can
check the certificate against it: edit either one and verification fails.
"""
from __future__ import annotations

import html
import json
import re

from .insight import stopped_actions
from .ledger import Ledger, canonical, sha256_hex
from .reconcile import Report

VERSION = 1


class CertificateError(Exception):
    pass


def build_certificate(ledger: Ledger, session_id: str, report: Report) -> dict:
    """Seal the session as it stands now. `report` is the current reconciliation (so cleared suspense items count)."""
    es = [e for e in ledger.entries() if e.get("session") == session_id]
    eod = next((e for e in reversed(es) if e["kind"] == "eod"), None)
    if eod is None:
        raise CertificateError("the day is not closed yet: close it first, then issue the certificate")
    intent = next(e for e in es if e["kind"] == "intent")
    actions = [e for e in es if e["kind"] == "action"]
    count = lambda d: sum(a["decision"] == d for a in actions)  # noqa: E731
    body = {
        "version": VERSION,
        "session": session_id,
        "task": intent["task"],
        "maker_model": intent.get("maker_model", ""),
        "checker_model": intent.get("checker_model", ""),
        "closed_at": eod["ts"],
        "verdict": "BALANCED" if report.balanced else "OUT OF BALANCE",
        "open_exceptions": len(report.open_exceptions),
        "actions": {"attempted": len(actions), "auto_approved": count("auto_approved"),
                    "checker_approved": count("checker_approved"), "held": count("held"),
                    "blocked": count("blocked")},
        "stopped": [{"seq": a["seq"], "tool": a["tool"], "target": a["target"][:80],
                     "reason": (a["reasons"][0] if a.get("reasons") else "")[:160]}
                    for a in stopped_actions(es)],
        "report_sha256": sha256_hex(canonical(report.to_dict())),
        "anchor": ledger.head(),
    }
    return {**body, "seal": sha256_hex(canonical(body))}


def verify_certificate(cert: dict, ledger: Ledger) -> tuple[bool, str]:
    body = {k: v for k, v in cert.items() if k != "seal"}
    if sha256_hex(canonical(body)) != cert.get("seal"):
        return False, "seal does not match: the certificate was edited"
    n, h = cert["anchor"]["seq"], cert["anchor"]["hash"]
    es = ledger.entries()
    if n < 1 or n > len(es) or es[n - 1]["hash"] != h:
        return False, f"ledger entry #{n} does not match the certificate's anchor"
    ok, bad, msg = ledger.verify(cert["anchor"])
    if not ok:
        return False, f"ledger is not intact: {msg}"
    return True, f"valid: sealed at ledger entry #{n}, chain intact up to the anchor"


def verify_certificate_html(text: str, ledger: Ledger) -> tuple[bool, str]:
    """Verify a certificate *file*: the embedded data, the ledger, and that the visible page was not edited."""
    cert = certificate_from_html(text)
    ok, msg = verify_certificate(cert, ledger)
    if not ok:
        return ok, msg
    if render_html(cert).strip() != text.strip():
        return False, "the visible text of this file differs from the sealed data: the page was edited"
    return True, msg


_JSON_RE = re.compile(r'<script type="application/json" id="talos-certificate">(.*?)</script>', re.S)


def certificate_from_html(text: str) -> dict:
    m = _JSON_RE.search(text)
    if not m:
        raise CertificateError("no Talos certificate data found in this file")
    return json.loads(m.group(1).replace("<\\/", "</"))


def render_html(cert: dict) -> str:
    e = html.escape
    ok = cert["verdict"] == "BALANCED"
    a = cert["actions"]
    rows = "".join(
        f"<tr><td>#{s['seq']}</td><td>{e(s['tool'])}</td><td class='mono'>{e(s['target'])}</td><td>{e(s['reason'])}</td></tr>"
        for s in cert["stopped"]) or "<tr><td colspan='4'>Nothing had to be stopped in this session.</td></tr>"
    data = json.dumps(cert, ensure_ascii=False).replace("</", "<\\/")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Talos day-close certificate {e(cert['session'])}</title>
<style>
:root{{--ink:#0b1020;--paper:#fbf8f1;--gold:#b88a1e;--ok:#0f7a55;--bad:#b42323;--mute:#5b6478}}
*{{box-sizing:border-box}}body{{margin:0;background:#e9e4d6;font-family:Inter,Segoe UI,system-ui,sans-serif;color:var(--ink);padding:32px 16px}}
.sheet{{max-width:820px;margin:0 auto;background:var(--paper);border:1px solid #d8cfb6;border-radius:6px;padding:44px 48px;
box-shadow:0 20px 60px rgba(11,16,32,.18);position:relative;overflow:hidden}}
.sheet:before{{content:"";position:absolute;inset:10px;border:2px solid var(--gold);border-radius:4px;pointer-events:none;opacity:.55}}
h1{{font-family:Georgia,serif;font-size:28px;margin:0 0 4px;letter-spacing:.5px}}
.sub{{color:var(--mute);font-size:13px;letter-spacing:2px;text-transform:uppercase}}
.stamp{{position:absolute;right:44px;top:40px;transform:rotate(-8deg);border:3px solid {'var(--ok)' if ok else 'var(--bad)'};
color:{'var(--ok)' if ok else 'var(--bad)'};padding:6px 14px;font-weight:800;letter-spacing:2px;border-radius:6px;font-size:15px}}
dl{{display:grid;grid-template-columns:150px 1fr;gap:8px 16px;margin:28px 0;font-size:14px}}dt{{color:var(--mute)}}dd{{margin:0}}
.mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}}
.kpis{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:8px 0 26px}}
.k{{border:1px solid #d8cfb6;border-radius:8px;padding:10px;text-align:center}}.k b{{display:block;font-size:24px}}.k span{{font-size:11px;color:var(--mute);text-transform:uppercase;letter-spacing:1px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid #e3dac0;vertical-align:top}}th{{color:var(--mute);font-weight:600}}
h2{{font-size:13px;letter-spacing:2px;text-transform:uppercase;color:var(--gold);margin:28px 0 8px}}
.seal{{margin-top:30px;padding:14px;background:#f1ecdd;border-radius:6px;font-size:12px}}
.foot{{margin-top:18px;font-size:11px;color:var(--mute);line-height:1.6}}
@media(max-width:640px){{.sheet{{padding:28px 20px}}.kpis{{grid-template-columns:repeat(2,1fr)}}.stamp{{position:static;display:inline-block;margin-top:12px}}dl{{grid-template-columns:1fr}}}}
@media print{{body{{background:#fff;padding:0}}.sheet{{box-shadow:none;border:none}}}}
</style></head><body><div class="sheet">
<div class="sub">Talos · dual control for AI agents</div>
<h1>Day-close certificate</h1>
<div class="stamp">{e(cert['verdict'])}</div>
<dl>
<dt>Session</dt><dd class="mono">{e(cert['session'])}</dd>
<dt>Task</dt><dd>{e(cert['task'])}</dd>
<dt>Maker model</dt><dd class="mono">{e(cert['maker_model'] or 'n/a')}</dd>
<dt>Checker model</dt><dd class="mono">{e(cert['checker_model'] or 'n/a')}</dd>
<dt>Day closed (UTC)</dt><dd>{e(cert['closed_at'])}</dd>
<dt>Open suspense items</dt><dd>{cert['open_exceptions']}</dd>
</dl>
<div class="kpis">
<div class="k"><b>{a['attempted']}</b><span>Attempted</span></div>
<div class="k"><b>{a['auto_approved']}</b><span>Auto</span></div>
<div class="k"><b>{a['checker_approved']}</b><span>Checker</span></div>
<div class="k"><b>{a['held']}</b><span>Held</span></div>
<div class="k"><b>{a['blocked']}</b><span>Blocked</span></div>
</div>
<h2>Stopped before execution ({len(cert['stopped'])})</h2>
<table><tr><th>#</th><th>Tool</th><th>Target</th><th>Reason</th></tr>{rows}</table>
<div class="seal"><b>Seal</b> <span class="mono">{e(cert['seal'])}</span><br>
<b>Ledger anchor</b> <span class="mono">entry #{cert['anchor']['seq']} · {e(cert['anchor']['hash'])}</span><br>
<b>Report hash</b> <span class="mono">{e(cert['report_sha256'])}</span></div>
<div class="foot">Verify with <span class="mono">python -m talos verify-cert this-file.html --ledger ledger.jsonl</span>.
Editing this certificate or the ledger breaks the seal. A hash chain cannot show that entries after the anchor were removed,
so keep a copy of the anchor somewhere Talos cannot write.</div>
<script type="application/json" id="talos-certificate">{data}</script>
</div></body></html>
"""
