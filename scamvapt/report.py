"""VAPT report — confirmed vulnerabilities, evidence, reproduction steps, PoC.

Four artifacts (HTML + PDF + JSON + MD). The report leads with CONFIRMED
findings — each with the proof, numbered steps to reproduce, a copy-paste PoC,
remediation and references — keeps `firm` findings clearly labelled, and
quarantines `tentative` hits in a separate "manual review" section so the
headline vulnerability count stays false-positive-free.
"""
from __future__ import annotations

import json
import math
from datetime import datetime

from jinja2 import Environment

from .vstate import VaptState, SEVERITY_ORDER

SEV_COLOR = {"critical": "#ff3b6b", "high": "#ff7a45", "medium": "#ffc43d",
             "low": "#4da3ff", "info": "#8b95a7"}
CONF_COLOR = {"confirmed": "#3ddb87", "firm": "#ffc43d", "tentative": "#8b95a7"}

# inline SVG icon set (stroke=currentColor) keyed by name
ICONS = {
    "shield": '<path d="M12 2 4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5z"/><path d="M9 12l2 2 4-4"/>',
    "bug": '<path d="M8 6a4 4 0 0 1 8 0M6 10h12M12 10v10M6 14H3M18 14h3M6 18H3M18 18h3M8 21l-2 1M16 21l2 1M8 3 6 1M16 3l2-2"/><rect x="8" y="6" width="8" height="12" rx="4"/>',
    "target": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.6"/>',
    "flame": '<path d="M12 2c2 4 6 5 6 10a6 6 0 0 1-12 0c0-2 1-3 2-4 .5 1 1.5 2 2 2 0-3 1-6 2-8z"/>',
    "layers": '<path d="M12 3 3 8l9 5 9-5z"/><path d="M3 13l9 5 9-5M3 18l9 5 9-5"/>',
    "list": '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    "flask": '<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3"/>',
    "wrench": '<path d="M14 6a4 4 0 0 0 5 5l-8 8a2.8 2.8 0 0 1-4-4z"/>',
    "search": '<circle cx="11" cy="11" r="8"/><path d="M21 21l-4.3-4.3"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "steps": '<path d="M4 20h4v-4h4v-4h4V8h4"/>',
    "book": '<path d="M4 5a2 2 0 0 1 2-2h12v18H6a2 2 0 0 1-2-2z"/><path d="M8 3v18"/>',
    "microscope": '<path d="M6 18h12M9 18a5 5 0 1 0 6-8M9 3l3 3-4 4-3-3zM7 8l3 3"/>',
}


def _codeify(text: str):
    """Escape HTML then turn `backtick` spans into <code> — safe for templates."""
    import html as _h
    import re as _re
    from markupsafe import Markup
    esc = _h.escape(str(text))
    esc = _re.sub(r"`([^`]+)`", r"<code>\1</code>", esc)
    return Markup(esc)


def build(st: VaptState) -> dict:
    st.finished = datetime.now()
    d = _to_dict(st)
    (st.outdir / "report.json").write_text(json.dumps(d, indent=2, default=str))
    env = Environment(autoescape=True)
    env.filters["codeify"] = _codeify
    (st.outdir / "report.html").write_text(env.from_string(_HTML).render(
        d=d, sevcolor=SEV_COLOR, confcolor=CONF_COLOR, donut=_donut(d["severity"]), icons=ICONS))
    (st.outdir / "summary.md").write_text(_md(d))
    arts = {"html": st.outdir / "report.html", "json": st.outdir / "report.json",
            "md": st.outdir / "summary.md"}
    try:
        p = _pdf(d, st.outdir / "report.pdf")
        if p:
            arts["pdf"] = p
    except Exception:  # noqa: BLE001
        pass
    return arts


def _to_dict(st: VaptState) -> dict:
    def vd(v):
        return {"class": v.vclass, "name": v.name, "severity": v.severity,
                "confidence": v.confidence, "url": v.url, "parameter": v.parameter,
                "payload": v.payload, "evidence": v.evidence, "tool": v.tool,
                "request": v.request, "remediation": v.remediation,
                "steps": v.steps, "references": v.references, "cwe": v.cwe}
    order = {"confirmed": 0, "firm": 1, "tentative": 2}
    sev = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    reportable = sorted(st.reportable, key=lambda v: (sev.get(v.severity, 9), order[v.confidence]))
    vulns = [vd(v) for v in reportable]
    counts = st.severity_counts(only_reportable=True)
    # AI-assisted triage / executive summary (offline fallback if no API)
    try:
        from . import ai
        ai_block = ai.analyze(vulns, counts, st.target_label)
    except Exception:  # noqa: BLE001
        ai_block = {}
    return {
        "target": st.target_label,
        "profile": st.profile_name,
        "started": st.started.strftime("%Y-%m-%d %H:%M:%S"),
        "finished": (st.finished or datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
        "duration": st.duration,
        "source_recon": st.source_recon,
        "stats": {
            "confirmed": len(st.confirmed),
            "reportable": len(st.reportable),
            "review": len(st.review),
            "classes_tested": len(st.surface),
            "targets": sum(len(v) for v in st.surface.values()),
            "tools": len(st.tools_used),
        },
        "severity": counts,
        "vulns": vulns,
        "review_items": [vd(v) for v in st.review],
        "surface": {k: len(v) for k, v in st.surface.items()},
        "tools_used": st.tools_used,
        "tool_coverage": _tool_coverage(),
        "ai": ai_block,
    }


def _tool_coverage() -> list:
    try:
        from scamrecon import runner
        rows = []
        for tool, e in sorted(runner.ledger().items()):
            if tool == "(pipeline)":
                continue
            status = ("timeout" if e.get("timeout") else "failed" if e.get("error")
                      else "ok" if e.get("ok") else "skipped")
            rows.append({"tool": tool, "status": status, "runs": e.get("ok", 0),
                         "timeouts": e.get("timeout", 0), "detail": e.get("detail", "")})
        return rows
    except Exception:  # noqa: BLE001
        return []


def _donut(counts):
    r = 54
    circ = 2 * math.pi * r
    total = sum(counts.values())
    segs, acc = [], 0.0
    if total == 0:
        return segs
    for s in SEVERITY_ORDER:
        n = counts.get(s, 0)
        if not n:
            continue
        seg = (n / total) * circ
        segs.append({"color": SEV_COLOR[s], "dasharray": f"{seg:.2f} {circ-seg:.2f}",
                     "dashoffset": f"{-acc:.2f}"})
        acc += seg
    return segs


def _md(d) -> str:
    s = d["stats"]
    lines = [f"# VAPT Report — {d['target']}",
             f"_{d['started']} → {d['finished']} ({d['duration']}), profile: {d['profile']}_", "",
             "## Summary",
             f"- **Confirmed vulnerabilities: {s['confirmed']}**",
             f"- Reportable (confirmed + firm): {s['reportable']}",
             f"- Severity — C:{d['severity']['critical']} H:{d['severity']['high']} M:{d['severity']['medium']}",
             f"- Classes tested: {s['classes_tested']} · Targets: {s['targets']} · Tools: {s['tools']}",
             f"- Needs manual review (tentative): {s['review']}", ""]
    if d["vulns"]:
        lines.append("## Confirmed / Firm Findings")
        for i, v in enumerate(d["vulns"], 1):
            lines += [f"### {i}. [{v['severity'].upper()}] {v['name']} — _{v['confidence']}_ ({v['cwe']})",
                      f"- **URL:** `{v['url']}`",
                      (f"- **Parameter:** `{v['parameter']}`" if v['parameter'] else ""),
                      (f"- **Payload:** `{v['payload']}`" if v['payload'] else ""),
                      f"- **Evidence:** {v['evidence']} (via {v['tool']})",
                      "- **Steps to reproduce:**"]
            for j, stp in enumerate(v["steps"], 1):
                lines.append(f"  {j}. {stp}")
            lines += [(f"- **PoC:** `{v['request']}`" if v['request'] else ""),
                      f"- **Remediation:** {v['remediation']}",
                      (f"- **References:** {', '.join(v['references'])}" if v['references'] else ""), ""]
    else:
        lines += ["## Result", "No vulnerabilities were confirmed on the tested surface (validated clean)."]
    return "\n".join(l for l in lines if l is not None)


# ── PDF (reportlab) ──────────────────────────────────────────
def _pdf(d, out_path):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                        TableStyle, HRFlowable, ListFlowable, ListItem)
    except Exception:
        return None
    INK = colors.HexColor("#16181d"); DIM = colors.HexColor("#5b6472")
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("T", parent=ss["Title"], fontSize=21, textColor=INK, alignment=0))
    ss.add(ParagraphStyle("Sub", parent=ss["Normal"], fontSize=9.5, textColor=DIM))
    ss.add(ParagraphStyle("H2", parent=ss["Heading2"], fontSize=13, textColor=INK, spaceBefore=12, spaceAfter=5))
    ss.add(ParagraphStyle("B", parent=ss["Normal"], fontSize=9, textColor=INK, leading=13))
    ss.add(ParagraphStyle("Bs", parent=ss["Normal"], fontSize=8.5, textColor=INK, leading=12))
    ss.add(ParagraphStyle("M", parent=ss["Normal"], fontName="Courier", fontSize=7.5, textColor=INK, leading=10))
    E = [Paragraph("Vulnerability Assessment &amp; Penetration Test", ss["T"]),
         Paragraph(f"<b>{d['target']}</b> · {d['started']} → {d['finished']} · {d['duration']} · profile {d['profile']}", ss["Sub"]),
         Paragraph("Only tool-confirmed vulnerabilities are reported. <b>confirmed</b> = proven exploitable; "
                   "<b>firm</b> = one step from proof. Each finding lists the exact steps to reproduce.", ss["Sub"]),
         Spacer(1, 6), HRFlowable(width="100%", color=colors.HexColor("#d11149"), thickness=1.4), Spacer(1, 8)]
    s = d["stats"]
    cards = [("CONFIRMED", s["confirmed"]), ("CRITICAL", d["severity"]["critical"]),
             ("HIGH", d["severity"]["high"]), ("CLASSES", s["classes_tested"]),
             ("TARGETS", s["targets"]), ("REVIEW", s["review"])]
    row = [[Paragraph(f"<b>{v}</b>", ParagraphStyle("n", fontSize=17, alignment=1, textColor=INK)) for _, v in cards],
           [Paragraph(l, ParagraphStyle("l", fontSize=6.5, alignment=1, textColor=DIM)) for l, _ in cards]]
    t = Table(row, colWidths=[86]*6)
    t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f6f8fc")),
                           ("BOX", (0,0), (-1,-1), 0.5, colors.HexColor("#e3e7ee")),
                           ("TOPPADDING", (0,0), (-1,0), 8), ("BOTTOMPADDING", (0,1), (-1,1), 8)]))
    E += [t, Spacer(1, 12)]
    if d["vulns"]:
        E.append(Paragraph(f"Confirmed / Firm Findings ({len(d['vulns'])})", ss["H2"]))
        for i, v in enumerate(d["vulns"], 1):
            col = colors.HexColor(SEV_COLOR.get(v["severity"], "#888"))
            body = [Paragraph(f'<font color="#{col.hexval()[2:]}"><b>{i}. [{v["severity"].upper()}]</b></font> '
                              f'<b>{v["name"]}</b> &nbsp;<font color="#3d8b5a">({v["confidence"]})</font> '
                              f'<font color="#5b6472">{v["cwe"]}</font>', ss["B"]),
                    Paragraph(f'URL: {v["url"]}', ss["M"]),
                    Paragraph((f'Param: {v["parameter"]} &nbsp; ' if v["parameter"] else "") +
                              (f'Payload: {v["payload"]} &nbsp; ' if v["payload"] else "") +
                              f'Evidence: {v["evidence"]}', ss["Bs"]),
                    Paragraph('<b>Steps to reproduce:</b>', ss["Bs"])]
            body.append(ListFlowable([ListItem(Paragraph(stp, ss["Bs"]), leftIndent=10)
                                      for stp in v["steps"]], bulletType="1", leftIndent=12))
            if v["request"]:
                body.append(Paragraph(f'PoC: {v["request"]}', ss["M"]))
            body.append(Paragraph(f'<font color="#3d8b5a"><b>Remediation:</b></font> {v["remediation"]}', ss["Bs"]))
            if v["references"]:
                body.append(Paragraph("Refs: " + " · ".join(v["references"]), ss["Bs"]))
            tbl = Table([[b] for b in body], colWidths=[500])
            tbl.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#fbfcfe")),
                                     ("BOX", (0,0), (-1,-1), 0.4, colors.HexColor("#e3e7ee")),
                                     ("LEFTPADDING", (0,0), (-1,-1), 8), ("RIGHTPADDING", (0,0), (-1,-1), 8),
                                     ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                                     ("LINEBEFORE", (0,0), (0,-1), 3, col)]))
            E += [tbl, Spacer(1, 7)]
    else:
        E.append(Paragraph("No vulnerabilities were confirmed on the tested surface.", ss["B"]))
    SimpleDocTemplate(str(out_path), pagesize=A4, topMargin=16*mm, bottomMargin=14*mm,
                      leftMargin=15*mm, rightMargin=15*mm).build(E)
    return out_path


_HTML = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VAPT Report — {{ d.target }}</title>
<style>
:root{--bg:#0a0e14;--bg2:#0d1220;--card:#121826;--card2:#161d2e;--border:#232c40;--txt:#dde3ee;--dim:#8b95a7;--faint:#5c6577;
--accent:#5b8cff;--crit:#ff3b6b;--high:#ff7a45;--med:#ffc43d;--low:#4da3ff;--info:#8b95a7;--ok:#3ddb87;
--mono:ui-monospace,"SF Mono",SFMono-Regular,"JetBrains Mono",Menlo,Consolas,monospace;--sans:"Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
body{background:radial-gradient(1100px 520px at 50% -190px,#241623,#0a0e14 62%);color:var(--txt);font-family:var(--sans);font-size:14px;line-height:1.55;padding:0 0 60px}
.wrap{max-width:1120px;margin:0 auto;padding:0 26px}.mono{font-family:var(--mono);font-size:12.5px}.muted{color:var(--dim)}.faint{color:var(--faint)}
header{background:linear-gradient(120deg,#2a1420,#12101c 62%);border-bottom:1px solid var(--border);padding:34px 0 30px;margin-bottom:24px;position:relative;overflow:hidden}
header::after{content:"";position:absolute;inset:0;background:radial-gradient(560px 200px at 84% 0,rgba(255,107,139,.14),transparent 70%)}
.hrow{display:flex;align-items:center;gap:16px;position:relative}
.logo{width:56px;height:56px;flex:0 0 auto;filter:drop-shadow(0 4px 14px rgba(255,107,139,.4))}
h1{font-size:26px;font-weight:800;letter-spacing:-.5px}h1 .g{background:linear-gradient(90deg,#ff6b8b,#ffa06b);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.meta{margin-top:8px;display:flex;flex-wrap:wrap;gap:8px}
.chip{display:inline-flex;gap:6px;align-items:center;background:#140e18;border:1px solid var(--border);border-radius:999px;padding:4px 12px;font-size:12.5px;color:var(--dim)}
.chip b{color:var(--txt)}.chip.ok{border-color:rgba(61,219,135,.4);color:var(--ok)}.chip.ok b{color:var(--ok)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:22px}
.kpi{background:linear-gradient(180deg,var(--card2),var(--card));border:1px solid var(--border);border-radius:14px;padding:16px 18px;position:relative;transition:transform .15s,border-color .15s}
.kpi:hover{transform:translateY(-2px);border-color:#3a2740}
.kpi .ico{position:absolute;top:14px;right:14px;opacity:.32}
.kpi .n{font-size:28px;font-weight:800;letter-spacing:-1px;line-height:1}
.kpi .l{color:var(--dim);font-size:10.5px;text-transform:uppercase;letter-spacing:.7px;margin-top:6px;font-weight:600}
.kpi.ok .n{color:var(--ok)}.kpi.crit .n{color:var(--crit)}.kpi.high .n{color:var(--high)}
.sevwrap{display:grid;grid-template-columns:150px 1fr;gap:24px;align-items:center;background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px 22px;margin-bottom:22px}
.leg{display:flex;flex-direction:column;gap:6px}.leg .row{display:flex;gap:9px;align-items:center;font-size:13px}.leg .dot{width:11px;height:11px;border-radius:3px}.leg b{margin-left:auto;font-variant-numeric:tabular-nums}
.stack{height:12px;border-radius:6px;overflow:hidden;display:flex;margin-top:14px;background:#0e1626}.stack span{height:100%}
.sechead{display:flex;align-items:center;gap:10px;margin:24px 0 12px}.sechead .si{color:var(--accent);display:flex}.sechead h2{font-size:16.5px;font-weight:700;color:#fff}.sechead .ct{color:var(--faint);font-size:13px;font-weight:600}
.exec{background:linear-gradient(180deg,#141d2e,#111826);border:1px solid var(--border);border-radius:14px;padding:18px 22px;margin-bottom:22px}
.exec-h{display:flex;align-items:center;gap:10px;margin-bottom:10px}.exec-h .si{color:#ffd06b;display:flex}.exec-h h2{font-size:17px;font-weight:800;color:#fff;flex:1}.exec-h .ct{color:var(--faint);font-size:11px}
.riskpill{font-size:12px;font-weight:800;padding:3px 12px;border-radius:999px}
.risk-critical{background:var(--crit);color:#fff}.risk-high{background:var(--high);color:#231007}.risk-medium{background:var(--med);color:#241c00}.risk-low{background:var(--ok);color:#04231a}
.exec-sum{font-size:14.5px;line-height:1.6;color:#e6ebf5;margin-bottom:8px}
.exec-sub{font-size:13px;color:var(--dim);margin:4px 0}.exec-sub b{color:#c5cde0}
.exec-cols{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin-top:12px}
.exec-lab{color:var(--accent);font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.exec-cols ol,.exec-cols ul{margin:0;padding-left:18px}.exec-cols li{font-size:13px;color:#c5cde0;margin:4px 0}
@media(max-width:720px){.exec-cols{grid-template-columns:1fr}}
.vuln{background:linear-gradient(180deg,var(--card2),var(--card));border:1px solid var(--border);border-left-width:4px;border-radius:13px;padding:17px 19px;margin-bottom:13px}
.vhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:800}
.sev-critical{background:var(--crit);color:#fff}.sev-high{background:var(--high);color:#231007}.sev-medium{background:var(--med);color:#241c00}.sev-low{background:var(--low);color:#04203f}.sev-info{background:var(--info)}
.conf{font-size:11px;font-weight:800;padding:2px 9px;border-radius:999px}
.vname{font-weight:700;font-size:15.5px;flex:1}
.tag{display:inline-block;background:#0e1626;color:#9fb0c9;border:1px solid var(--border);border-radius:6px;padding:1px 8px;font-size:11px}
.kv{display:grid;grid-template-columns:96px 1fr;gap:5px 12px;font-size:13px;margin-top:4px}
.kv .k{color:var(--faint);text-transform:uppercase;font-size:10px;letter-spacing:.5px;padding-top:3px}
.repro{margin-top:12px;background:#0b1322;border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.repro .rt{display:flex;align-items:center;gap:7px;color:var(--accent);font-weight:700;font-size:12.5px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.repro ol{margin:0;padding-left:20px;counter-reset:step}
.repro li{margin:5px 0;font-size:13px;color:#c5cde0}
.repro li code,.kv code{background:#0a1120;border:1px solid var(--border);border-radius:5px;padding:0 5px;font-family:var(--mono);font-size:12px;color:#8bb0ff}
.poc{background:#06140c;border:1px solid rgba(61,219,135,.28);border-radius:8px;padding:9px 12px;margin-top:10px;font-family:var(--mono);font-size:12px;color:#8ef0bd;overflow-x:auto}
.ev{background:#0a1120;border:1px solid var(--border);border-radius:8px;padding:8px 11px;margin-top:8px;font-family:var(--mono);font-size:12px;color:#9fb0c9;overflow-x:auto}
.fix{margin-top:10px;padding:9px 13px;border-radius:9px;background:rgba(61,219,135,.07);border:1px solid rgba(61,219,135,.25);font-size:13px}.fix b{color:var(--ok)}
.refs{margin-top:9px;font-size:12px}.refs a{color:#7aa2ff;text-decoration:none;margin-right:10px}
.empty{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:34px;text-align:center;color:var(--dim)}
details{background:var(--card);border:1px solid var(--border);border-radius:12px;margin-top:10px}summary{padding:14px 18px;cursor:pointer;font-weight:700;color:var(--dim)}
table{width:100%;border-collapse:collapse;font-size:13px}td{padding:6px 10px;border-bottom:1px solid #1a2233}
.meth{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:16px 18px;margin-top:10px}
.foot{color:var(--faint);text-align:center;margin-top:32px;font-size:12px}
@media print{body{background:#fff;color:#111}.vuln,.kpi,.sevwrap{break-inside:avoid}}
</style></head><body>
<header><div class="wrap"><div class="hrow">
<svg class="logo" viewBox="0 0 24 24" fill="none" stroke="url(#gg)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
<defs><linearGradient id="gg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ff6b8b"/><stop offset="1" stop-color="#ffa06b"/></linearGradient></defs>
{{ icons.shield|safe }}</svg>
<div><h1><span class="g">VAPT</span> Report</h1>
<div class="meta"><span class="chip mono"><b>{{ d.target }}</b></span>
<span class="chip">{{ d.started }} → {{ d.finished }}</span><span class="chip">⏱ {{ d.duration }}</span>
<span class="chip">profile <b>{{ d.profile }}</b></span><span class="chip ok">✓ <b>{{ d.stats.confirmed }} confirmed</b></span></div>
</div></div></div></header>
<div class="wrap">

{% macro ic(name,cls='') -%}<svg class="{{cls}}" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">{{ icons[name]|safe }}</svg>{%- endmacro %}

<div class="grid">
<div class="kpi ok"><span class="ico">{{ ic('check') }}</span><div class="n">{{ d.stats.confirmed }}</div><div class="l">Confirmed Vulns</div></div>
<div class="kpi crit"><span class="ico">{{ ic('flame') }}</span><div class="n">{{ d.severity.critical }}</div><div class="l">Critical</div></div>
<div class="kpi high"><span class="ico">{{ ic('bug') }}</span><div class="n">{{ d.severity.high }}</div><div class="l">High</div></div>
<div class="kpi"><span class="ico">{{ ic('layers') }}</span><div class="n">{{ d.stats.classes_tested }}</div><div class="l">Classes Tested</div></div>
<div class="kpi"><span class="ico">{{ ic('target') }}</span><div class="n">{{ '{:,}'.format(d.stats.targets) }}</div><div class="l">Targets</div></div>
<div class="kpi"><span class="ico">{{ ic('microscope') }}</span><div class="n">{{ d.stats.review }}</div><div class="l">Manual Review</div></div>
</div>

{% if d.ai %}
<div class="exec">
 <div class="exec-h"><span class="si">{{ ic('book') }}</span><h2>Executive Summary</h2>
  <span class="riskpill risk-{{ d.ai.business_risk|lower }}">Business risk: {{ d.ai.business_risk }}</span>
  <span class="ct">{{ d.ai.engine }}</span></div>
 <p class="exec-sum">{{ d.ai.executive_summary }}</p>
 {% if d.ai.risk_rationale %}<p class="exec-sub"><b>Risk rationale.</b> {{ d.ai.risk_rationale }}</p>{% endif %}
 {% if d.ai.attack_narrative %}<p class="exec-sub"><b>Likely attack path.</b> {{ d.ai.attack_narrative }}</p>{% endif %}
 <div class="exec-cols">
  {% if d.ai.top_priorities %}<div><div class="exec-lab">Remediation priorities</div><ol>{% for p in d.ai.top_priorities %}<li>{{ p }}</li>{% endfor %}</ol></div>{% endif %}
  {% if d.ai.notable_findings %}<div><div class="exec-lab">Most notable</div><ul>{% for nf in d.ai.notable_findings %}<li>{{ nf }}</li>{% endfor %}</ul></div>{% endif %}
 </div>
</div>
{% endif %}

{% if d.vulns %}
<div class="sevwrap">
<svg viewBox="0 0 140 140" width="150" height="150">
<circle cx="70" cy="70" r="54" fill="none" stroke="#1a2233" stroke-width="18"/>
{% for s in donut %}<circle cx="70" cy="70" r="54" fill="none" stroke="{{ s.color }}" stroke-width="18" stroke-dasharray="{{ s.dasharray }}" stroke-dashoffset="{{ s.dashoffset }}" transform="rotate(-90 70 70)"/>{% endfor %}
<text x="70" y="66" text-anchor="middle" fill="#fff" font-size="28" font-weight="800" font-family="sans-serif">{{ d.stats.reportable }}</text>
<text x="70" y="84" text-anchor="middle" fill="#8b95a7" font-size="9" letter-spacing="1" font-family="sans-serif">REPORTABLE</text></svg>
<div><div class="leg">{% for s in ['critical','high','medium','low','info'] %}<div class="row"><span class="dot" style="background:{{ sevcolor[s] }}"></span>{{ s|capitalize }}<b>{{ d.severity[s] }}</b></div>{% endfor %}</div>
<div class="stack">{% set tot = d.stats.reportable %}{% for s in ['critical','high','medium','low','info'] %}{% if d.severity[s] %}<span style="width:{{ (d.severity[s]/tot*100)|round(1) }}%;background:{{ sevcolor[s] }}"></span>{% endif %}{% endfor %}</div></div>
</div>

<div class="sechead"><span class="si">{{ ic('target') }}</span><h2>Confirmed &amp; Firm Findings</h2><span class="ct">{{ d.vulns|length }} · each with steps to reproduce</span></div>
{% for v in d.vulns %}
<div class="vuln" style="border-left-color:{{ sevcolor[v.severity] }}">
<div class="vhead"><span class="pill sev-{{ v.severity }}">{{ v.severity }}</span>
<span class="vname">{{ loop.index }}. {{ v.name }}</span>
<span class="conf" style="background:{{ confcolor[v.confidence] }}22;color:{{ confcolor[v.confidence] }};border:1px solid {{ confcolor[v.confidence] }}55">{{ v.confidence }}</span>
<span class="tag">{{ v.class }}</span><span class="tag">{{ v.cwe }}</span></div>
<div class="kv">
<div class="k">Target</div><div class="mono"><a href="{{ v.url }}" style="color:#7aa2ff">{{ v.url }}</a></div>
{% if v.parameter %}<div class="k">Parameter</div><div><code>{{ v.parameter }}</code></div>{% endif %}
{% if v.payload %}<div class="k">Payload</div><div><code>{{ v.payload }}</code></div>{% endif %}
<div class="k">Evidence</div><div>{{ v.evidence }} <span class="faint">· via {{ v.tool }}</span></div>
</div>
{% if v.evidence %}<div class="ev">{{ v.evidence }}</div>{% endif %}
{% if v.steps %}<div class="repro"><div class="rt">{{ ic('steps') }} Steps to reproduce</div><ol>{% for s in v.steps %}<li>{{ s|codeify }}</li>{% endfor %}</ol></div>{% endif %}
{% if v.request %}<div class="poc">$ {{ v.request }}</div>{% endif %}
<div class="fix"><b>Remediation.</b> {{ v.remediation }}</div>
{% if v.references %}<div class="refs">{% for r in v.references %}<a href="{{ r }}">↗ {{ r|truncate(60) }}</a>{% endfor %}</div>{% endif %}
</div>
{% endfor %}
{% else %}
<div class="empty">{{ ic('check') }}<br><br>No vulnerabilities were <b>confirmed</b> on the tested surface.<br>
<span class="faint">A clean result here is validated, not assumed — every candidate was actively tested.</span></div>
{% endif %}

{% if d.review_items %}
<details><summary>🔬 Needs Manual Review — {{ d.review_items|length }} tentative signal(s) (NOT counted as vulns)</summary>
<div style="padding:0 18px 16px"><table><tbody>
{% for v in d.review_items %}<tr><td><span class="pill sev-{{ v.severity }}">{{ v.severity }}</span></td><td>{{ v.name }}</td><td class="mono"><a href="{{ v.url }}" style="color:#7aa2ff">{{ v.url|truncate(66) }}</a></td><td class="faint">{{ v.tool }}</td></tr>{% endfor %}
</tbody></table></div></details>
{% endif %}

<div class="sechead"><span class="si">{{ ic('flask') }}</span><h2>Methodology &amp; Tooling</h2></div>
<div class="meth"><div class="kv">
<div class="k">Recon src</div><div class="mono faint">{{ d.source_recon or 'ad-hoc URL / list' }}</div>
<div class="k">Approach</div><div>Confirmation-first: every finding was actively tested and only reported when a tool proved it. Candidates come from recon's curl-validated attack vectors, widened via hidden-parameter discovery.</div>
<div class="k">Surface</div><div>{% for c, n in d.surface.items() %}<span class="tag">{{ c }}: {{ n }}</span> {% endfor %}</div>
<div class="k">Tools</div><div>{% for t, n in d.tools_used.items() %}<span class="tag">{{ t }} · {{ n }}</span> {% endfor %}</div>
</div></div>

{% if d.tool_coverage %}
<div class="sechead"><span class="si">{{ ic('microscope') }}</span><h2>Tool Coverage</h2><span class="ct">what ran · what stalled or was skipped</span></div>
<div class="meth"><table><thead><tr><th>Tool</th><th>Status</th><th>OK runs</th><th>Timeouts</th><th>Note</th></tr></thead><tbody>
{% for t in d.tool_coverage %}
<tr><td class="mono">{{ t.tool }}</td>
<td>{% if t.status=='ok' %}<span style="color:var(--ok)">✓ ok</span>{% elif t.status=='timeout' %}<span style="color:var(--high)">⏱ timeout</span>{% elif t.status=='failed' %}<span style="color:var(--crit)">✗ failed</span>{% else %}<span class="faint">– skipped</span>{% endif %}</td>
<td>{{ t.runs }}</td><td>{{ t.timeouts }}</td><td class="faint">{{ t.detail }}</td></tr>
{% endfor %}
</tbody></table></div>
{% endif %}

<div class="foot">Generated by ScamVapt · {{ d.finished }}<br>confirmation-first: only tool-proven vulnerabilities are reported as findings</div>
</div></body></html>"""
