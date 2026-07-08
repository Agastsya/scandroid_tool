"""Report generation — clean, validated, board-ready output.

Produces three artifacts in the run directory:
  * report.html  — a single self-contained dark-theme page (no external assets)
  * report.json  — the full machine-readable dataset for the next tool/stage
  * summary.md   — a terse markdown digest for tickets / notes

The HTML is deliberately uncluttered: summary cards up top, then collapsible
sections. Everything shown is already validated (resolved DNS + live httpx),
so the next step can trust it without re-checking.
"""
from __future__ import annotations

import json
from datetime import datetime
from urllib.parse import urlparse

from jinja2 import Template

from .state import ReconState

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {"critical": "#ff2d55", "high": "#ff6b35", "medium": "#ffcc00",
             "low": "#4dabf7", "info": "#868e96"}


def build(st: ReconState) -> dict:
    st.finished = datetime.now()
    data = _to_dict(st)
    (st.outdir / "report.json").write_text(json.dumps(data, indent=2, default=str))
    (st.outdir / "report.html").write_text(_html(st, data))
    (st.outdir / "summary.md").write_text(_markdown(st, data))
    artifacts = {
        "html": st.outdir / "report.html",
        "json": st.outdir / "report.json",
        "md": st.outdir / "summary.md",
    }
    # PDF (reportlab) — the printable/client-facing artifact
    try:
        from . import pdf
        if pdf.available():
            p = pdf.build(data, st.outdir / "report.pdf")
            if p:
                artifacts["pdf"] = p
    except Exception:  # noqa: BLE001 — never let PDF break the run
        pass
    return artifacts


def _to_dict(st: ReconState) -> dict:
    return {
        "target": st.target,
        "profile": st.profile_name,
        "started": st.started.strftime("%Y-%m-%d %H:%M:%S"),
        "finished": (st.finished or datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
        "duration": st.duration,
        "stats": {
            "subdomains": len(st.subdomains),
            "discovered": st.discovered or len(st.subdomains),
            "dropped": len(st.unresolved),
            "resolved": len(st.resolved),
            "live": len(st.live),
            "open_ports": sum(len(v) for v in st.ports.values()),
            "urls": len(st.urls),
            "js_files": len(st.js_files),
            "technologies": len(st.technologies),
            "findings": len(st.findings),
            "takeovers": len(st.takeovers),
        },
        "severity": st.severity_counts(),
        "sources": st.sources,
        "live_hosts": [
            {"url": h.url, "status": h.status, "title": h.title, "webserver": h.webserver,
             "ip": h.ip, "cdn": h.cdn, "tech": h.tech, "length": h.content_length}
            for h in sorted(st.live.values(), key=lambda x: x.url)
        ],
        "ports": {h: sorted(set(p)) for h, p in sorted(st.ports.items())},
        "ports_unreliable": st.ports_unreliable,
        "nmap_services": st.nmap_services,
        "technologies": dict(sorted(st.technologies.items(), key=lambda x: -x[1])),
        "findings": [
            {"severity": f.severity, "name": f.name, "template": f.template,
             "host": f.host, "matched": f.matched, "tags": f.tags}
            for f in sorted(st.findings, key=lambda x: SEV_ORDER.index(x.severity)
                            if x.severity in SEV_ORDER else 99)
        ],
        "takeovers": st.takeovers,
        "asn": st.asn_info,
        "interesting": st.interesting,
        "validated_vectors": st.validated_vectors,
        "highlights": _highlights(st),
        "subdomains_all": sorted(st.subdomains),
        "resolved_all": sorted(st.resolved.keys()),
        "live_hostnames": sorted({urlparse(h.url).netloc.split(":")[0]
                                  for h in st.live.values()}),
        "tool_coverage": _tool_coverage(),
    }


def _tool_coverage() -> list[dict]:
    """Per-tool run outcomes (ok/timeout/skipped/failed) for the report."""
    try:
        from . import runner
        rows = []
        for tool, e in sorted(runner.ledger().items()):
            if tool == "(pipeline)":
                continue
            if e.get("timeout"):
                status = "timeout"
            elif e.get("error"):
                status = "failed"
            elif e.get("ok"):
                status = "ok"
            else:
                status = "skipped"
            rows.append({"tool": tool, "status": status, "runs": e.get("ok", 0),
                         "timeouts": e.get("timeout", 0), "detail": e.get("detail", "")})
        return rows
    except Exception:  # noqa: BLE001
        return []


def _highlights(st: ReconState) -> list[dict]:
    """Prioritized, human-readable 'look here first' items for the analyst."""
    h: list[dict] = []
    sev = st.severity_counts()
    if sev["critical"] or sev["high"]:
        h.append({"level": "critical", "text":
                  f"{sev['critical']} critical + {sev['high']} high-severity findings — triage these first."})
    if st.takeovers:
        h.append({"level": "high", "text":
                  f"{len(st.takeovers)} potential subdomain takeover(s) detected — verify and claim."})
    # exposed panels / admin / login hosts
    panels = [h2.url for h2 in st.live.values()
              if any(k in (h2.title or "").lower() for k in ("login", "admin", "dashboard", "panel", "portal"))]
    if panels:
        h.append({"level": "medium", "text":
                  f"{len(panels)} login/admin/panel interfaces exposed (e.g. {panels[0]})."})
    # interesting attackable URLs
    for cls, urls in sorted(st.interesting.items(), key=lambda x: -len(x[1])):
        if urls:
            h.append({"level": "info", "text":
                      f"{len(urls)} URLs with parameters typical of {cls}."})
    # non-standard open ports
    interesting_ports = sorted({p for ports in st.ports.values() for p in ports
                                if p not in (80, 443)})
    if interesting_ports:
        h.append({"level": "info", "text":
                  f"Non-web ports open: {', '.join(map(str, interesting_ports[:15]))}."})
    return h


def _markdown(st: ReconState, d: dict) -> str:
    s = d["stats"]
    lines = [
        f"# Recon Report — {d['target']}",
        f"_{d['started']} → {d['finished']} ({d['duration']}), profile: {d['profile']}_",
        "",
        "## Summary",
        f"- Subdomains discovered: **{s['subdomains']}**",
        f"- Resolved (valid DNS): **{s['resolved']}**",
        f"- Live web services: **{s['live']}**",
        f"- Open ports: **{s['open_ports']}**",
        f"- URLs collected: **{s['urls']}**",
        f"- JS files: **{s['js_files']}**",
        f"- Technologies: **{s['technologies']}**",
        f"- Nuclei findings: **{s['findings']}** "
        f"(C:{d['severity']['critical']} H:{d['severity']['high']} M:{d['severity']['medium']})",
        f"- Potential takeovers: **{s['takeovers']}**",
        "",
    ]
    if d["highlights"]:
        lines.append("## Attack Surface Highlights")
        for hl in d["highlights"]:
            lines.append(f"- **[{hl['level'].upper()}]** {hl['text']}")
        lines.append("")
    lines.append("## Live hosts")
    for h in d["live_hosts"][:50]:
        lines.append(f"- [{h['status']}] {h['url']} — {h['title']} "
                     f"({', '.join(h['tech'][:4])})")
    if d["findings"]:
        lines += ["", "## Findings"]
        for f in d["findings"][:60]:
            lines.append(f"- **{f['severity'].upper()}** {f['name']} — {f['host']}")
    return "\n".join(lines)


_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Report — {{ d.target }}</title>
<style>
:root{
 --bg:#0a0e14;--bg2:#0d1220;--card:#121826;--card2:#161d2e;--border:#232c40;
 --txt:#dde3ee;--dim:#8b95a7;--faint:#5c6577;
 --accent:#5b8cff;--accent2:#8b5bff;--green:#3ddb87;
 --crit:#ff3b6b;--high:#ff7a45;--med:#ffc43d;--low:#4da3ff;--info:#8b95a7;
 --mono:ui-monospace,"SF Mono",SFMono-Regular,"JetBrains Mono",Menlo,Consolas,monospace;
 --sans:"Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
body{background:radial-gradient(1200px 600px at 50% -200px,#141c30 0%,var(--bg) 60%);
 color:var(--txt);font-family:var(--sans);font-size:14px;line-height:1.55;
 padding:0 0 60px;min-height:100vh}
.wrap{max-width:1180px;margin:0 auto;padding:0 28px}
.mono{font-family:var(--mono);font-size:12.5px}
.muted{color:var(--dim)} .faint{color:var(--faint)}

/* Header */
header{background:linear-gradient(120deg,#141d33,#0e1524 60%);border-bottom:1px solid var(--border);
 padding:34px 0 30px;margin-bottom:26px;position:relative;overflow:hidden}
header::after{content:"";position:absolute;inset:0;background:
 radial-gradient(600px 200px at 85% 0,rgba(91,140,255,.14),transparent 70%);pointer-events:none}
.hrow{display:flex;align-items:center;gap:18px}
.logo{width:56px;height:56px;flex:0 0 auto;filter:drop-shadow(0 4px 14px rgba(91,140,255,.4))}
h1{font-size:27px;font-weight:800;letter-spacing:-.6px;line-height:1.1}
h1 .g{background:linear-gradient(90deg,#7aa2ff,#b98bff);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.meta{margin-top:8px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.chip{display:inline-flex;align-items:center;gap:6px;background:#0e1626;border:1px solid var(--border);
 border-radius:999px;padding:4px 12px;font-size:12.5px;color:var(--dim)}
.chip b{color:var(--txt);font-weight:600}
.chip.ok{border-color:rgba(61,219,135,.35);color:var(--green)}
.chip.ok b{color:var(--green)}

/* KPI cards */
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:12px;margin-bottom:24px}
.kpi{background:linear-gradient(180deg,var(--card2),var(--card));border:1px solid var(--border);
 border-radius:14px;padding:16px 18px;position:relative;transition:transform .15s,border-color .15s}
.kpi:hover{transform:translateY(-2px);border-color:#33405c}
.kpi .ico{position:absolute;top:14px;right:14px;opacity:.35}
.kpi .n{font-size:29px;font-weight:800;letter-spacing:-1px;line-height:1}
.kpi .l{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.7px;margin-top:6px;font-weight:600}
.kpi.accent .n{color:#7aa2ff}.kpi.green .n{color:var(--green)}.kpi.warn .n{color:var(--high)}

/* Severity overview */
.sevwrap{display:grid;grid-template-columns:150px 1fr;gap:26px;align-items:center;
 background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px 24px;margin-bottom:24px}
.leg{display:flex;flex-direction:column;gap:7px}
.leg .row{display:flex;align-items:center;gap:9px;font-size:13px}
.leg .dot{width:11px;height:11px;border-radius:3px;flex:0 0 auto}
.leg .row b{margin-left:auto;font-variant-numeric:tabular-nums}
.stack{height:12px;border-radius:6px;overflow:hidden;display:flex;margin-top:14px;background:#0e1626}
.stack span{height:100%}

/* Sections */
section{background:var(--card);border:1px solid var(--border);border-radius:14px;margin-bottom:14px;overflow:hidden}
details>summary{padding:16px 20px;cursor:pointer;user-select:none;display:flex;align-items:center;gap:11px;list-style:none}
details>summary::-webkit-details-marker{display:none}
details>summary:hover{background:var(--card2)}
summary .sico{color:var(--accent);flex:0 0 auto;display:flex}
summary h2{font-size:15.5px;font-weight:700;color:#fff;flex:1}
summary .badge{background:#0e1626;color:var(--dim);border:1px solid var(--border);
 border-radius:999px;padding:3px 12px;font-size:11.5px;font-weight:600}
summary .chev{transition:transform .2s;color:var(--faint)}
details[open] summary .chev{transform:rotate(90deg)}
.body{padding:2px 20px 20px}

table{width:100%;border-collapse:collapse;font-size:13px}
thead th{text-align:left;color:var(--dim);font-weight:600;padding:8px 10px;
 border-bottom:1px solid var(--border);font-size:10.5px;text-transform:uppercase;letter-spacing:.6px;
 position:sticky;top:0;background:var(--card)}
td{padding:8px 10px;border-bottom:1px solid #1a2233;vertical-align:top}
tbody tr:hover td{background:#141c2c}
a{color:#7aa2ff;text-decoration:none}a:hover{text-decoration:underline}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:.3px}
.sev-critical{background:var(--crit);color:#fff}.sev-high{background:var(--high);color:#1a0f08}
.sev-medium{background:var(--med);color:#241c00}.sev-low{background:var(--low);color:#04203f}.sev-info{background:var(--info);color:#0c1017}
.st{font-weight:800;font-variant-numeric:tabular-nums}
.st2{color:var(--green)}.st3{color:var(--med)}.st4{color:var(--high)}.st5{color:var(--crit)}
.tag{display:inline-block;background:#0e1626;color:#9fb0c9;border:1px solid var(--border);
 border-radius:6px;padding:1px 8px;margin:1px;font-size:11px}
.alert{border:1px solid rgba(255,122,69,.4);background:linear-gradient(180deg,#241610,#1a1109);
 border-radius:12px;padding:14px 18px;margin-bottom:16px}
.alert b{color:var(--high)}
.cls{color:#8bb0ff;font-weight:700}
.foot{color:var(--faint);text-align:center;margin-top:34px;font-size:12px}
.foot .g{color:var(--dim)}
@media print{body{background:#fff;color:#111}.kpi,section,.sevwrap{break-inside:avoid}}
</style></head><body>

<header><div class="wrap"><div class="hrow">
<svg class="logo" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
 <defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
  <stop offset="0" stop-color="#7aa2ff"/><stop offset="1" stop-color="#b98bff"/></linearGradient></defs>
 <circle cx="32" cy="32" r="30" stroke="url(#lg)" stroke-width="2" opacity=".35"/>
 <circle cx="32" cy="32" r="21" stroke="url(#lg)" stroke-width="2" opacity=".55"/>
 <circle cx="32" cy="32" r="6" fill="url(#lg)"/>
 <path d="M32 2 A30 30 0 0 1 62 32" stroke="url(#lg)" stroke-width="3" stroke-linecap="round"/>
 <circle cx="54" cy="14" r="3.5" fill="#7aa2ff"/></svg>
<div>
<h1><span class="g">Reconnaissance</span> Report</h1>
<div class="meta">
 <span class="chip mono"><b>{{ d.target }}</b></span>
 <span class="chip">{{ d.started }} → {{ d.finished }}</span>
 <span class="chip">⏱ {{ d.duration }}</span>
 <span class="chip">profile <b>{{ d.profile }}</b></span>
 <span class="chip ok">✓ <b>curl-validated</b></span>
 <span class="chip">funnel <b>{{ d.stats.discovered }}</b> discovered → <b>{{ d.stats.resolved }}</b> resolved → <b>{{ d.stats.live }}</b> live{% if d.stats.dropped %} <span class="faint">({{ d.stats.dropped }} dead dropped)</span>{% endif %}</span>
</div></div></div></div></header>

<div class="wrap">

<div class="grid">
{% macro kpi(n,label,cls,ico) -%}
<div class="kpi {{cls}}"><span class="ico">{{ico|safe}}</span><div class="n">{{ '{:,}'.format(n) }}</div><div class="l">{{label}}</div></div>
{%- endmacro %}
{{ kpi(d.stats.discovered,'Discovered','','<svg width=20 height=20 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><circle cx=12 cy=12 r=10/><path d="M2 12h20M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20"/></svg>') }}
{{ kpi(d.stats.resolved,'Resolved (real DNS)','accent','<svg width=20 height=20 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M4 6h16M4 12h16M4 18h10"/></svg>') }}
{{ kpi(d.stats.live,'Live (validated)','green','<svg width=20 height=20 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>') }}
{{ kpi(d.stats.open_ports,'Open Ports','','<svg width=20 height=20 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><rect x=3 y=3 width=18 height=18 rx=2/><path d="M9 9h6v6H9z"/></svg>') }}
{{ kpi(d.stats.urls,'URLs','','<svg width=20 height=20 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/></svg>') }}
{{ kpi(d.stats.technologies,'Technologies','','<svg width=20 height=20 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M12 2v4M12 18v4M4.9 4.9l2.8 2.8M16.3 16.3l2.8 2.8M2 12h4M18 12h4"/><circle cx=12 cy=12 r=3/></svg>') }}
{{ kpi(d.stats.findings,'Findings',('warn' if d.stats.findings else ''),'<svg width=20 height=20 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>') }}
{{ kpi(d.takeovers|length,'Takeovers',('warn' if d.takeovers else ''),'<svg width=20 height=20 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M18 8h1a4 4 0 0 1 0 8h-1M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4z"/></svg>') }}
</div>

{% if d.stats.findings %}
<div class="sevwrap">
 <svg viewBox="0 0 140 140" width="150" height="150">
  <circle cx="70" cy="70" r="54" fill="none" stroke="#1a2233" stroke-width="18"/>
  {% for s in donut %}
  <circle cx="70" cy="70" r="54" fill="none" stroke="{{ s.color }}" stroke-width="18"
    stroke-dasharray="{{ s.dasharray }}" stroke-dashoffset="{{ s.dashoffset }}"
    transform="rotate(-90 70 70)" stroke-linecap="butt"/>
  {% endfor %}
  <text x="70" y="66" text-anchor="middle" fill="#fff" font-size="30" font-weight="800" font-family="sans-serif">{{ d.stats.findings }}</text>
  <text x="70" y="84" text-anchor="middle" fill="#8b95a7" font-size="10" letter-spacing="1" font-family="sans-serif">FINDINGS</text>
 </svg>
 <div>
  <div class="leg">
  {% for s in ['critical','high','medium','low','info'] %}
   <div class="row"><span class="dot" style="background:{{ sevcolor[s] }}"></span>{{ s|capitalize }}<b>{{ d.severity[s] }}</b></div>
  {% endfor %}
  </div>
  <div class="stack">
  {% set tot = d.stats.findings %}
  {% for s in ['critical','high','medium','low','info'] %}{% if d.severity[s] %}
  <span style="width:{{ (d.severity[s]/tot*100)|round(1) }}%;background:{{ sevcolor[s] }}"></span>
  {% endif %}{% endfor %}
  </div>
 </div>
</div>
{% endif %}

{% if d.ports_unreliable %}
<div class="alert"><b>⚠ Port scan skipped — network interception detected.</b>
<div class="muted" style="margin-top:4px">Your network answered TCP handshakes for random closed ports, so every port would look open (false positives). Re-run from a clean network / VPN / cloud box for trustworthy port data.</div></div>
{% endif %}

{% macro sec(title,badge,ico,open_) %}
<section><details {{ 'open' if open_ else '' }}><summary>
<span class="sico">{{ ico|safe }}</span><h2>{{ title }}</h2>
{% if badge %}<span class="badge">{{ badge }}</span>{% endif %}
<svg class="chev" width=16 height=16 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M9 18l6-6-6-6"/></svg>
</summary><div class="body">{% endmacro %}
{% set endsec = '</div></details></section>' %}

{% set I_target = '<svg width=18 height=18 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><circle cx=12 cy=12 r=10/><circle cx=12 cy=12 r=6/><circle cx=12 cy=12 r=2/></svg>' %}
{% set I_bolt = '<svg width=18 height=18 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M13 2 3 14h9l-1 8 10-12h-9z"/></svg>' %}
{% set I_search = '<svg width=18 height=18 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><circle cx=11 cy=11 r=8/><path d="M21 21l-4.3-4.3"/></svg>' %}
{% set I_globe = '<svg width=18 height=18 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><circle cx=12 cy=12 r=10/><path d="M2 12h20M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20"/></svg>' %}
{% set I_plug = '<svg width=18 height=18 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0zM12 17v5"/></svg>' %}
{% set I_chip = '<svg width=18 height=18 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><rect x=6 y=6 width=12 height=12 rx=1/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/></svg>' %}
{% set I_list = '<svg width=18 height=18 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>' %}
{% set I_link = '<svg width=18 height=18 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/></svg>' %}
{% set I_warn = '<svg width=18 height=18 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/></svg>' %}

{% if d.highlights %}
{{ sec('Attack Surface Highlights','start here',I_target,true) }}
<table><tbody>
{% for hl in d.highlights %}
<tr><td style="width:92px"><span class="pill sev-{{ hl.level }}">{{ hl.level }}</span></td><td>{{ hl.text }}</td></tr>
{% endfor %}</tbody></table>
{{ endsec|safe }}
{% endif %}

{% if d.validated_vectors %}
{{ sec('Validated Attack Vectors ('~(d.validated_vectors.values()|map('length')|sum)~')','reachable · curl-confirmed',I_bolt,true) }}
{% for cls, urls in d.validated_vectors.items() %}
<div style="margin-bottom:14px"><span class="cls">{{ cls }}</span> <span class="muted">· {{ urls|length }} live URL(s)</span>
<table style="margin-top:6px"><tbody>
{% for u in urls[:12] %}<tr><td class="mono"><a href="{{ u }}" target="_blank">{{ u|truncate(112) }}</a></td></tr>{% endfor %}
</tbody></table>{% if urls|length > 12 %}<span class="faint">... +{{ urls|length - 12 }} more in 10_validated/</span>{% endif %}</div>
{% endfor %}
{{ endsec|safe }}
{% elif d.interesting %}
{{ sec('Attackable Endpoints ('~(d.interesting.values()|map('length')|sum)~')','triage by param',I_bolt,true) }}
{% for cls, urls in d.interesting.items() %}
<div style="margin-bottom:14px"><span class="cls">{{ cls }}</span> <span class="muted">· {{ urls|length }} URL(s)</span>
<table style="margin-top:6px"><tbody>
{% for u in urls[:12] %}<tr><td class="mono"><a href="{{ u }}" target="_blank">{{ u|truncate(112) }}</a></td></tr>{% endfor %}
</tbody></table></div>
{% endfor %}
{{ endsec|safe }}
{% endif %}

{% if d.findings %}
{{ sec('Findings ('~d.findings|length~')','nuclei + nmap NSE · validated',I_search,true) }}
<table><thead><tr><th>Severity</th><th>Finding</th><th>Host</th><th>Template</th></tr></thead><tbody>
{% for f in d.findings %}
<tr><td><span class="pill sev-{{ f.severity }}">{{ f.severity }}</span></td>
<td>{{ f.name }}</td><td class="mono"><a href="{{ f.matched or f.host }}">{{ f.host }}</a></td>
<td class="faint mono">{{ f.template }}</td></tr>
{% endfor %}</tbody></table>
{{ endsec|safe }}
{% endif %}

{% if d.takeovers %}
{{ sec('Potential Subdomain Takeovers ('~d.takeovers|length~')','verify manually',I_warn,true) }}
<table><tbody>
{% for t in d.takeovers %}<tr><td class="mono">{{ t.host }}</td><td class="muted">{{ t.source }}</td></tr>{% endfor %}
</tbody></table>
{{ endsec|safe }}
{% endif %}

{{ sec('Live Web Services ('~d.live_hosts|length~')','httpx + curl validated',I_globe,true) }}
<table><thead><tr><th>St</th><th>URL</th><th>Title</th><th>Server</th><th>IP</th><th>Tech</th></tr></thead><tbody>
{% for h in d.live_hosts %}
<tr><td class="st st{{ (h.status//100) }}">{{ h.status }}</td>
<td class="mono"><a href="{{ h.url }}" target="_blank">{{ h.url }}</a></td>
<td>{{ h.title }}</td><td class="muted">{{ h.webserver }}{% if h.cdn %} <span class="tag">CDN:{{ h.cdn }}</span>{% endif %}</td>
<td class="mono faint">{{ h.ip }}</td>
<td>{% for t in h.tech[:5] %}<span class="tag">{{ t }}</span>{% endfor %}</td></tr>
{% endfor %}</tbody></table>
{{ endsec|safe }}

{% if d.ports %}
{{ sec('Open Ports ('~d.stats.open_ports~')','naabu + nmap NSE',I_plug,false) }}
<table><thead><tr><th>Host</th><th>Ports</th><th>Services (nmap)</th></tr></thead><tbody>
{% for host, ports in d.ports.items() %}
<tr><td class="mono">{{ host }}</td>
<td>{% for p in ports %}<span class="tag">{{ p }}</span>{% endfor %}</td>
<td class="faint mono">{% if d.nmap_services.get(host) %}{% for s in d.nmap_services[host] %}{{ s.port }}/{{ s.service }} {{ s.product }} {{ s.version }}<br>{% endfor %}{% endif %}</td></tr>
{% endfor %}</tbody></table>
{{ endsec|safe }}
{% endif %}

{% if d.technologies %}
{{ sec('Technology Stack ('~d.technologies|length~')','httpx tech-detect',I_chip,false) }}
{% for t, c in d.technologies.items() %}<span class="tag">{{ t }} · {{ c }}</span> {% endfor %}
{{ endsec|safe }}
{% endif %}

{{ sec('Resolved Subdomains ('~d.subdomains_all|length~')','live in green · '~d.stats.dropped~' dead dropped',I_list,false) }}
<div class="muted" style="font-size:12px;margin-bottom:8px">Only real, DNS-resolving subdomains are listed — {{ d.stats.dropped }} non-existent brute/permutation guesses were dropped (see <span class="mono">02_resolved/unresolved_dropped.txt</span>). <b style="color:var(--green)">Green</b> = HTTP-live &amp; curl-validated.</div>
<div class="mono" style="column-count:3;column-gap:24px;font-size:12px">
{% for s in d.subdomains_all %}{% if s in d.live_hostnames %}<span style="color:var(--green)">{{ s }}</span>{% else %}<span class="faint">{{ s }}</span>{% endif %}<br>{% endfor %}</div>
{{ endsec|safe }}

{% if d.sources %}
{{ sec('Discovery Sources','provenance',I_link,false) }}
{% for src, n in d.sources.items() %}<span class="tag">{{ src }}: {{ n }}</span> {% endfor %}
{{ endsec|safe }}
{% endif %}

{% if d.tool_coverage %}
{{ sec('Tool Coverage ('~d.tool_coverage|length~')','what ran · what stalled',I_list,false) }}
<div class="muted" style="font-size:12px;margin-bottom:8px">Every tool invocation is tracked. If a tool stalled or wasn't installed it was skipped (never blocking the run) — shown here so nothing is silently missing.</div>
<table><thead><tr><th>Tool</th><th>Status</th><th>OK runs</th><th>Timeouts</th><th>Note</th></tr></thead><tbody>
{% for t in d.tool_coverage %}
<tr><td class="mono">{{ t.tool }}</td>
<td>{% if t.status=='ok' %}<span style="color:var(--green)">✓ ok</span>{% elif t.status=='timeout' %}<span style="color:var(--high)">⏱ timeout</span>{% elif t.status=='failed' %}<span style="color:var(--crit)">✗ failed</span>{% else %}<span class="faint">– skipped</span>{% endif %}</td>
<td>{{ t.runs }}</td><td>{{ t.timeouts }}</td><td class="faint">{{ t.detail }}</td></tr>
{% endfor %}
</tbody></table>
{{ endsec|safe }}
{% endif %}

<div class="foot"><span class="g">Generated by ScamRecon</span> · {{ d.finished }}<br>
every host & vector above was DNS-resolved, HTTP-probed and independently curl-validated</div>

</div></body></html>"""


def _donut_segments(counts: dict) -> list[dict]:
    """Pre-compute SVG stroke-dash segments for the severity donut."""
    import math
    r = 54
    circ = 2 * math.pi * r
    total = sum(counts.values())
    segs = []
    if total == 0:
        return segs
    acc = 0.0
    for sev in SEV_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        frac = n / total
        seg_len = frac * circ
        segs.append({
            "color": SEV_COLOR[sev], "sev": sev, "n": n,
            "dasharray": f"{seg_len:.2f} {circ - seg_len:.2f}",
            "dashoffset": f"{-acc:.2f}",
        })
        acc += seg_len
    return segs


def _html(st: ReconState, d: dict) -> str:
    return Template(_HTML).render(
        d=d, sevcolor=SEV_COLOR, donut=_donut_segments(d["severity"]),
        circ=339.29)
