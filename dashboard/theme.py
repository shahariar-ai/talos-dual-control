"""Visual layer of the Talos dashboard: CSS and small HTML/SVG components.

Everything here is pure string building, so the look can change without touching the logic in app.py.
"""
from __future__ import annotations

import base64
from html import escape as e

PALETTE = {
    "bg": "#0A0F1E", "surface": "#111A30", "surface2": "#17233F", "line": "#25335A",
    "text": "#E6EAF2", "mute": "#8B97B5", "gold": "#E3B341",
    "ok": "#34D399", "info": "#60A5FA", "warn": "#FBBF24", "bad": "#F87171", "grey": "#94A3B8",
}
TIER_COLOR = {"LOW": PALETTE["ok"], "MEDIUM": PALETTE["warn"], "HIGH": PALETTE["bad"]}
DECISION_COLOR = {"auto_approved": PALETTE["ok"], "checker_approved": PALETTE["info"], "held": PALETTE["warn"],
                  "blocked": PALETTE["bad"], "approved": PALETTE["info"], "rejected": PALETTE["bad"],
                  "error": PALETTE["grey"]}
TONE_COLOR = {"ok": PALETTE["ok"], "info": PALETTE["info"], "warn": PALETTE["warn"], "bad": PALETTE["bad"],
              "mute": PALETTE["grey"]}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
:root{--bg:#0A0F1E;--s1:#111A30;--s2:#17233F;--line:#25335A;--tx:#E6EAF2;--mute:#8B97B5;--gold:#E3B341;
--ok:#34D399;--info:#60A5FA;--warn:#FBBF24;--bad:#F87171}
html,body,[class*="css"],.stApp{font-family:'Inter',system-ui,sans-serif}
.stApp{background:radial-gradient(1200px 520px at 12% -8%,rgba(227,179,65,.10),transparent 60%),
radial-gradient(900px 480px at 100% 0%,rgba(96,165,250,.10),transparent 55%),var(--bg)}
.block-container{padding-top:1.6rem;max-width:1280px}
header[data-testid="stHeader"]{background:transparent}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0E1630,#0A0F1E);border-right:1px solid var(--line)}
[data-testid="stSidebar"] .stButton>button{font-weight:700}
h1,h2,h3{letter-spacing:-.01em}
code,pre{font-family:'JetBrains Mono',ui-monospace,monospace!important}

.tl-hero{display:flex;align-items:center;gap:20px;padding:22px 26px;border:1px solid var(--line);border-radius:18px;
background:linear-gradient(135deg,rgba(23,35,63,.92),rgba(17,26,48,.92));position:relative;overflow:hidden;margin-bottom:18px}
.tl-hero:after{content:"";position:absolute;right:-60px;top:-60px;width:260px;height:260px;border-radius:50%;
background:radial-gradient(circle,rgba(227,179,65,.22),transparent 70%)}
.tl-hero h1{margin:0;font-size:34px;font-weight:800;color:#fff;line-height:1.05}
.tl-hero .tag{color:var(--mute);margin-top:6px;font-size:14.5px;max-width:760px;line-height:1.5}
.tl-pills{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.pill{display:inline-flex;align-items:center;gap:7px;padding:4px 11px;border-radius:999px;font-size:12px;font-weight:600;
border:1px solid var(--line);background:rgba(10,15,30,.6);color:var(--tx)}
.pill i{width:8px;height:8px;border-radius:50%;display:inline-block}
.pill.ok{border-color:rgba(52,211,153,.5);color:var(--ok)}.pill.ok i{background:var(--ok);box-shadow:0 0 10px var(--ok)}
.pill.bad{border-color:rgba(248,113,113,.6);color:var(--bad)}.pill.bad i{background:var(--bad);box-shadow:0 0 10px var(--bad)}
.pill.gold{border-color:rgba(227,179,65,.55);color:var(--gold)}.pill.gold i{background:var(--gold)}
.pill.info{border-color:rgba(96,165,250,.5);color:var(--info)}.pill.info i{background:var(--info)}

[data-testid="stMetric"]{background:linear-gradient(180deg,var(--s2),var(--s1));border:1px solid var(--line);border-radius:14px;
padding:14px 16px;box-shadow:0 8px 24px rgba(0,0,0,.25)}
[data-testid="stMetricLabel"] p{color:var(--mute);font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-weight:600}
[data-testid="stMetricLabel"],[data-testid="stMetricLabel"] p{white-space:normal!important;overflow:visible!important;text-overflow:clip!important;letter-spacing:.05em}
[data-testid="stMetricValue"]{font-weight:800}

.stTabs [data-baseweb="tab-list"]{gap:6px;border-bottom:1px solid var(--line)}
.stTabs [data-baseweb="tab"]{height:44px;border-radius:10px 10px 0 0;padding:0 16px;color:var(--mute);font-weight:600}
.stTabs [aria-selected="true"]{color:var(--gold)!important;background:rgba(227,179,65,.08)}
.stTabs [data-baseweb="tab-highlight"]{background:var(--gold)!important}
[data-testid="stAlert"]{border-radius:12px;border:1px solid var(--line)}
[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:12px;overflow:hidden}
div[data-testid="stVerticalBlockBorderWrapper"]{border-radius:14px}
.stButton>button,.stDownloadButton>button{border-radius:10px;font-weight:600}
.stButton>button[kind="primary"]{background:linear-gradient(135deg,#F2C75A,#D99A1E);color:#1A1204;border:none}

.card{background:linear-gradient(180deg,var(--s2),var(--s1));border:1px solid var(--line);border-radius:14px;padding:16px 18px;height:100%}
.card h4{margin:0 0 6px;font-size:15px;color:#fff}.card p{margin:0;color:var(--mute);font-size:13px;line-height:1.55}
.card .big{font-size:30px;font-weight:800;color:var(--gold);line-height:1}
.grid{display:grid;gap:14px}.g3{grid-template-columns:repeat(3,1fr)}.g2{grid-template-columns:repeat(2,1fr)}
@media(max-width:900px){.g3,.g2{grid-template-columns:1fr}.tl-hero{flex-direction:column;align-items:flex-start}}

.flow{display:flex;align-items:stretch;gap:0;flex-wrap:wrap;margin:6px 0 2px}
.node{flex:1 1 150px;min-width:150px;background:var(--s1);border:1px solid var(--line);border-radius:14px;padding:14px;position:relative}
.node b{display:block;color:#fff;font-size:14px}.node span{color:var(--mute);font-size:12px;line-height:1.45;display:block;margin-top:4px}
.node .n{position:absolute;top:-10px;left:12px;background:var(--gold);color:#1A1204;font-weight:800;font-size:11px;border-radius:999px;padding:1px 8px}
.arrow{align-self:center;color:var(--gold);font-size:20px;padding:0 6px}

.threat{display:flex;gap:14px;align-items:flex-start;padding:12px 14px;border:1px solid var(--line);border-radius:12px;background:var(--s1);margin-bottom:10px}
.threat .cnt{min-width:46px;height:46px;border-radius:12px;background:rgba(248,113,113,.14);color:var(--bad);font-weight:800;font-size:22px;
display:flex;align-items:center;justify-content:center}
.threat b{color:#fff;font-size:14px}.threat p{margin:2px 0 4px;color:var(--mute);font-size:12.5px}
.threat>div:last-child{min-width:0;flex:1}
.threat code{font-size:11.5px;color:var(--tx);background:rgba(255,255,255,.05);padding:1px 6px;border-radius:5px;display:inline-block;margin:2px 4px 0 0;max-width:100%;white-space:normal;word-break:break-all}

.story{position:relative;margin-left:8px;padding-left:22px;border-left:2px solid var(--line)}
.step{position:relative;padding:8px 0 12px}
.step:before{content:"";position:absolute;left:-29px;top:13px;width:12px;height:12px;border-radius:50%;background:var(--c);box-shadow:0 0 0 4px var(--bg),0 0 12px var(--c)}
.step b{color:#fff;font-size:14px}.step p{margin:2px 0 0;color:var(--mute);font-size:12.5px}.step.now b{color:var(--gold)}
.step.future{opacity:.28}
.gauge{height:12px;border-radius:999px;background:#0C1428;border:1px solid var(--line);overflow:hidden}
.gauge>div{height:100%;border-radius:999px}
.gl{display:flex;justify-content:space-between;color:var(--mute);font-size:12px;margin:0 0 6px}
.small{color:var(--mute);font-size:12.5px}
</style>
"""

LOGO = """<svg width="76" height="76" viewBox="0 0 96 96" xmlns="http://www.w3.org/2000/svg" aria-label="Talos">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#F6D675"/><stop offset="1" stop-color="#C98A12"/></linearGradient></defs>
<path d="M48 6 L84 20 V46 C84 68 68 82 48 90 C28 82 12 68 12 46 V20 Z" fill="#0A0F1E" stroke="url(#g)" stroke-width="4"/>
<path d="M30 34 H66 M48 34 V70" stroke="url(#g)" stroke-width="7" stroke-linecap="round"/>
<circle cx="48" cy="52" r="4" fill="#0A0F1E"/>
<path d="M34 24 L48 18 L62 24" stroke="#34D399" stroke-width="3" fill="none" stroke-linecap="round" opacity=".9"/></svg>"""


def _img(svg: str, width: str = "100%", alt: str = "", extra: str = "") -> str:
    """Inline SVG is stripped by Streamlit's HTML sanitiser, so ship it as a data-URI image."""
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f'<img alt="{e(alt)}" src="data:image/svg+xml;base64,{b64}" style="width:{width};{extra}"/>'


def hero(live: bool, intact: bool | None, extra: str = "") -> str:
    mode = ('<span class="pill gold"><i></i>LIVE · Nemotron on Nebius Token Factory</span>' if live else
            '<span class="pill info"><i></i>OFFLINE SIMULATION · scripted agent</span>')
    seal = ""
    if intact is not None:
        seal = ('<span class="pill ok"><i></i>Ledger intact</span>' if intact else
                '<span class="pill bad"><i></i>Ledger BROKEN</span>')
    return (f'<div class="tl-hero">{_img(LOGO, "76px", "Talos", "flex:none")}<div><h1>Talos</h1>'
            '<div class="tag">Dual control for AI agents. A Maker does the work, an independent Checker reviews it, '
            'a Teller limits its risk, a hash-chained ledger records everything, and at the end of the day '
            'Talos reconciles what you asked, what the agent planned and what really happened.</div>'
            f'<div class="tl-pills">{mode}{seal}{extra}</div></div></div>')


def pill(text: str, kind: str = "gold") -> str:
    return f'<span class="pill {kind}"><i></i>{e(text)}</span>'


def flow() -> str:
    steps = [("Maker agent", "Nemotron 3 Super plans and proposes every tool call."),
             ("Risk engine", "Deterministic rules set the floor: LOW, MEDIUM or HIGH. Hard blocks never run."),
             ("Checker model", "A different Nemotron model reviews MEDIUM actions. It never sees file contents or the Maker's reasoning."),
             ("Teller limits", "Every attempt costs points, even blocked ones. Overspend and the agent is frozen."),
             ("Ledger and close", "Hash-chained record, three-way reconciliation, rollback and a sealed certificate.")]
    out = []
    for i, (t, d) in enumerate(steps, 1):
        out.append(f'<div class="node"><span class="n">{i}</span><b>{e(t)}</b><span>{e(d)}</span></div>')
        if i < len(steps):
            out.append('<div class="arrow">›</div>')
    return f'<div class="flow">{"".join(out)}</div>'


def control_cards() -> str:
    items = [("Maker-checker", "Two different models, so one model's mistake or compromise cannot approve itself. Four-eyes is enforced at start-up."),
             ("Teller limits", "Trainee, Standard or Senior authority. A misbehaving agent burns its own budget and freezes."),
             ("Hash-chained ledger", "Edit or delete a past entry and the chain breaks at the exact line. Secrets are stored as fingerprints."),
             ("Three-way match", "Intent versus plan versus actual, then actual versus the real disk. Differences go to suspense."),
             ("Reversal entries", "Every write can be rolled back, and rollback refuses to overwrite later human work."),
             ("Sealed certificate", "A printable day-close receipt that can be verified against the ledger by anyone who holds both.")]
    cells = "".join(f'<div class="card"><h4>{e(t)}</h4><p>{e(d)}</p></div>' for t, d in items)
    return f'<div class="grid g3">{cells}</div>'


def gauge(used: int, budget: int, frozen: bool = False) -> str:
    pct = 0 if not budget else min(100, round(100 * used / budget))
    col = PALETTE["bad"] if frozen or pct >= 90 else PALETTE["warn"] if pct >= 60 else PALETTE["ok"]
    return (f'<div class="gl"><span>Risk budget</span><span>{used} / {budget} points</span></div>'
            f'<div class="gauge"><div style="width:{pct}%;background:linear-gradient(90deg,{col}99,{col})"></div></div>')


def timeline_svg(actions: list[dict], budget: int, w: int = 760, h: int = 230) -> str:
    """Risk budget burned across the agent's actions. One dot per action, coloured by decision."""
    if not actions:
        return '<div class="small">No actions yet.</div>'
    pad_l, pad_r, pad_t, pad_b = 44, 18, 16, 34
    n = len(actions)
    ymax = max(budget, max(a["teller"]["used"] for a in actions if a.get("teller")) if any(a.get("teller") for a in actions) else budget) or 1
    px = lambda i: pad_l + (w - pad_l - pad_r) * (i / max(n - 1, 1))  # noqa: E731
    py = lambda v: pad_t + (h - pad_t - pad_b) * (1 - v / ymax)  # noqa: E731
    pts = [(px(i), py(a["teller"]["used"] if a.get("teller") else 0)) for i, a in enumerate(actions)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"{pad_l},{py(0):.1f} {line} {pts[-1][0]:.1f},{py(0):.1f}"
    grid = "".join(
        f'<line x1="{pad_l}" x2="{w - pad_r}" y1="{py(v):.1f}" y2="{py(v):.1f}" stroke="#25335A" stroke-dasharray="3 5"/>'
        f'<text x="{pad_l - 8}" y="{py(v) + 4:.1f}" fill="#8B97B5" font-size="11" text-anchor="end">{int(v)}</text>'
        for v in (0, ymax / 2, ymax))
    limit = (f'<line x1="{pad_l}" x2="{w - pad_r}" y1="{py(budget):.1f}" y2="{py(budget):.1f}" stroke="#F87171" stroke-width="1.5"/>'
             f'<text x="{w - pad_r}" y="{py(budget) - 6:.1f}" fill="#F87171" font-size="11" text-anchor="end">limit {budget}</text>')
    dots = []
    for (x, y), a in zip(pts, actions):
        c = DECISION_COLOR.get(a["decision"], PALETTE["grey"])
        dots.append(f'<g><title>#{a["seq"]} {e(a["tool"])} {e(a["target"][:40])}: {e(a["decision"])}</title>'
                    f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7.5" fill="{c}" opacity=".18"/>'
                    f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{c}"/></g>')
    labels = "".join(f'<text x="{x:.1f}" y="{h - 12}" fill="#8B97B5" font-size="10.5" text-anchor="middle">#{a["seq"]}</text>'
                     for (x, _), a in zip(pts, actions))
    legend = "".join(f'<span class="pill" style="margin-right:6px"><i style="background:{c}"></i>{e(k.replace("_", " "))}</span>'
                     for k, c in (("auto_approved", PALETTE["ok"]), ("checker_approved", PALETTE["info"]),
                                  ("held", PALETTE["warn"]), ("blocked", PALETTE["bad"])))
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" font-family="Inter,Segoe UI,sans-serif">'
            f'<defs><linearGradient id="ar" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#E3B341" stop-opacity=".35"/>'
            f'<stop offset="1" stop-color="#E3B341" stop-opacity="0"/></linearGradient></defs>{grid}{limit}'
            f'<polygon points="{area}" fill="url(#ar)"/><polyline points="{line}" fill="none" stroke="#E3B341" stroke-width="2.4" '
            f'stroke-linejoin="round"/>{"".join(dots)}{labels}</svg>')
    return _img(svg, "100%", "Risk budget over actions") + f'<div style="margin-top:6px">{legend}</div>'


def threat_cards(rows: list[dict]) -> str:
    if not rows:
        return '<div class="card"><h4>Nothing needed stopping</h4><p>Every action in this session was within policy.</p></div>'
    out = []
    for r in rows:
        ex = "".join(f"<code>{e(x)}</code>" for x in r["examples"])
        out.append(f'<div class="threat"><div class="cnt">{r["count"]}</div><div><b>{e(r["name"])}</b>'
                   f'<p>{e(r["blurb"])}</p>{ex}</div></div>')
    return "".join(out)


def story(items: list[tuple[dict, bool]]) -> str:
    """items: [(narrated entry, is_current_or_past)] ; the last True item is highlighted as 'now'."""
    last_on = max((i for i, (_, on) in enumerate(items) if on), default=-1)
    out = []
    for i, (n, on) in enumerate(items):
        cls = "step" + (" now" if i == last_on else "") + ("" if on else " future")
        out.append(f'<div class="{cls}" style="--c:{TONE_COLOR[n["tone"]]}"><b>{e(n["title"])}</b>'
                   f'<p>{e(n["detail"])}</p></div>')
    return f'<div class="story">{"".join(out)}</div>'
