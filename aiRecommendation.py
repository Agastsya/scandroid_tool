#!/usr/bin/env python3
"""AI security analysis — turns raw scan logs into a validated, structured report.

Improvements over the original:
  * FIXED a critical bug where the log chunk was never sent to the model (the
    prompt was a static string) — the AI now actually analyses your scan data.
  * Strong structured prompt → JSON findings (severity, CVSS, evidence, impact,
    remediation commands, references).
  * Produces a polished HTML report (aiReport/ai_report.html) in addition to the
    text report, which is kept in the exact format patchingSystem.py and
    backend.js expect (chunk sections + ```json blocks).
  * API key read from $GROQ_API_KEY (falls back to the bundled key), model from
    $GROQ_MODEL. Degrades gracefully when the API is unreachable.
"""
from __future__ import annotations

import html as _html
import json
import os
import re
import sys
import time

import requests

# ── Configuration ────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "reports")
LOG_FILE_PATH = os.path.join(LOG_DIR, "scanner_file.txt")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "aiReport")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "ai_report.txt")
HTML_FILE = os.path.join(OUTPUT_DIR, "ai_report.html")

API_URL = os.environ.get("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

MAX_CHARS_PER_REQUEST = 6000
CHUNK_OVERHEAD = 400
MAX_RETRIES = 4
RETRY_DELAY = 7
REQUEST_DELAY = 4
API_TIMEOUT = 60

API_KEY = os.environ.get("GROQ_API_KEY") or "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"
HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEV_COLOR = {"Critical": "#ff3b6b", "High": "#ff7a45", "Medium": "#ffc43d",
             "Low": "#4da3ff", "Info": "#8b95a7"}

SYSTEM_PROMPT = (
    "You are a principal security analyst with deep offensive and defensive "
    "expertise. You are given a slice of raw security-scan/audit log output. "
    "Identify only GENUINE, evidence-backed security issues present in the log — "
    "do not invent findings. For each issue return strict JSON. Respond with ONE "
    "JSON object only, no prose, using exactly this schema:\n"
    '{"findings":[{"title":"","severity":"Critical|High|Medium|Low|Info",'
    '"cvss":0.0,"category":"","affected":"","evidence":"<quote the log line>",'
    '"description":"","impact":"","remediation":{"summary":"","commands":["exact shell commands"]},'
    '"references":["https://..."]}]}\n'
    "If the slice contains no real security issue, return {\"findings\":[]}. "
    "Commands must be concrete and copy-pasteable."
)


def read_and_chunk_log(path: str) -> list[str]:
    try:
        with open(path, "r") as f:
            data = f.read()
    except Exception as e:  # noqa: BLE001
        print(f"Error reading log file: {e}")
        return []
    chunks, cur, count = [], [], 0
    for para in data.split("\n\n"):
        if count + len(para) > (MAX_CHARS_PER_REQUEST - CHUNK_OVERHEAD) and cur:
            chunks.append("\n\n".join(cur)); cur, count = [], 0
        cur.append(para); count += len(para)
    if cur:
        chunks.append("\n\n".join(cur))
    return [c for c in chunks if c.strip()]


def query_with_retry(chunk: str, chunk_num: int) -> dict | None:
    """Send the ACTUAL chunk to the model (this was the original's core bug)."""
    user_prompt = (
        "Analyse this security scan log slice and report genuine findings as JSON "
        "per the schema. Quote the exact evidence lines.\n\n"
        f"----- LOG SLICE {chunk_num} -----\n{chunk}\n----- END -----"
    )
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 1500,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.post(API_URL, headers=HEADERS, json=payload, timeout=API_TIMEOUT)
            if r.status_code == 400:  # some models reject response_format — retry without
                payload.pop("response_format", None)
                r = requests.post(API_URL, headers=HEADERS, json=payload, timeout=API_TIMEOUT)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.Timeout:
            print(f"⌛ timeout chunk {chunk_num}, attempt {attempt}/{MAX_RETRIES}")
            time.sleep(RETRY_DELAY * attempt)
        except requests.exceptions.RequestException as e:
            print(f"⚠️ API error: {e}")
            return None
    return None


def parse_findings(content: str) -> list[dict]:
    """Extract findings[] from the model response (tolerant of stray prose)."""
    blob = content
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if m:
        blob = m.group(0)
    try:
        data = json.loads(blob)
    except Exception:
        return []
    findings = data.get("findings", []) if isinstance(data, dict) else []
    out = []
    for f in findings:
        if not isinstance(f, dict) or not f.get("title"):
            continue
        sev = str(f.get("severity", "Info")).capitalize()
        if sev not in SEV_ORDER:
            sev = "Info"
        rem = f.get("remediation", {}) or {}
        if isinstance(rem, str):
            rem = {"summary": rem, "commands": []}
        out.append({
            "title": str(f.get("title", ""))[:200],
            "severity": sev,
            "cvss": f.get("cvss", ""),
            "category": f.get("category", ""),
            "affected": f.get("affected", ""),
            "evidence": str(f.get("evidence", ""))[:600],
            "description": f.get("description", ""),
            "impact": f.get("impact", ""),
            "remediation": {"summary": rem.get("summary", ""),
                            "commands": [c for c in (rem.get("commands") or []) if c]},
            "references": [r for r in (f.get("references") or []) if r],
        })
    return out


def dedup(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in sorted(findings, key=lambda x: SEV_ORDER.index(x["severity"])):
        key = f["title"].strip().lower()
        if key in seen:
            continue
        seen.add(key); out.append(f)
    return out


# ── Output: text (backward-compatible) + HTML ────────────────
def write_text_report(findings: list[dict]) -> None:
    """Keep the format patchingSystem.py + backend.js parse: chunk sections + ```json."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    lines = ["🛡️ SECURITY ANALYSIS REPORT\n"]
    for i, f in enumerate(findings, 1):
        block = {
            "type": f["title"], "severity": f["severity"],
            "description": f["description"], "location": f["affected"],
            "log_entry": f["evidence"],
            "steps": [{"description": f["remediation"]["summary"] or f["title"],
                       "commands": f["remediation"]["commands"],
                       "notes": f["impact"]}],
            "references": f["references"],
        }
        lines.append(f"\n\n--- Chunk {i} Analysis ---")
        lines.append(f"**Vulnerability {i}: {f['title']}**")
        lines.append(f"Severity: {f['severity']}")
        lines.append(f"```json\n{json.dumps(block, indent=2)}\n```")
    with open(OUTPUT_FILE, "w") as fh:
        fh.write("\n".join(lines))
    print(f"✅ text report → {OUTPUT_FILE}")


def write_html_report(findings: list[dict]) -> None:
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    total = len(findings) or 1
    cards = "".join(
        f'<div class="kpi" style="--c:{SEV_COLOR[s]}"><div class="n">{counts[s]}</div>'
        f'<div class="l">{s}</div></div>' for s in SEV_ORDER)
    bar = "".join(
        f'<span style="width:{counts[s]/total*100:.1f}%;background:{SEV_COLOR[s]}"></span>'
        for s in SEV_ORDER if counts[s])
    items = []
    for f in findings:
        cmds = "".join(f'<div class="cmd">$ {_html.escape(c)}</div>'
                       for c in f["remediation"]["commands"])
        refs = "".join(f'<a href="{_html.escape(r)}">{_html.escape(r)}</a> '
                       for r in f["references"])
        items.append(f"""
      <div class="vuln" style="border-left-color:{SEV_COLOR[f['severity']]}">
        <div class="vh"><span class="pill" style="background:{SEV_COLOR[f['severity']]}">{f['severity']}</span>
          <span class="vt">{_html.escape(f['title'])}</span>
          {'<span class="cvss">CVSS '+str(f['cvss'])+'</span>' if f['cvss'] else ''}
          <span class="cat">{_html.escape(str(f['category']))}</span></div>
        {'<p class="desc">'+_html.escape(f['description'])+'</p>' if f['description'] else ''}
        {'<div class="kv"><b>Affected</b> '+_html.escape(str(f['affected']))+'</div>' if f['affected'] else ''}
        {'<div class="kv"><b>Impact</b> '+_html.escape(f['impact'])+'</div>' if f['impact'] else ''}
        {'<div class="ev">'+_html.escape(f['evidence'])+'</div>' if f['evidence'] else ''}
        {'<div class="rem"><b>Remediation.</b> '+_html.escape(f['remediation']['summary'])+'</div>' if f['remediation']['summary'] else ''}
        {cmds}
        {'<div class="refs">'+refs+'</div>' if refs else ''}
      </div>""")
    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>AI Security Analysis</title>
<style>
:root{{--bg:#0a0e14;--card:#121826;--border:#232c40;--txt:#dde3ee;--dim:#8b95a7;--faint:#5c6577;
--sans:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;--mono:ui-monospace,"SF Mono",Menlo,monospace}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:radial-gradient(1100px 500px at 50% -180px,#161c30,#0a0e14 62%);color:var(--txt);font-family:var(--sans);font-size:14px;line-height:1.55;padding:0 0 60px}}
.wrap{{max-width:1000px;margin:0 auto;padding:0 26px}}
header{{background:linear-gradient(120deg,#151d33,#0e1524);border-bottom:1px solid var(--border);padding:30px 0;margin-bottom:22px}}
h1{{font-size:24px;font-weight:800}}h1 .g{{background:linear-gradient(90deg,#7aa2ff,#b98bff);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}}
.sub{{color:var(--dim);margin-top:6px;font-size:13px}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px}}
.kpi{{background:var(--card);border:1px solid var(--border);border-top:3px solid var(--c);border-radius:12px;padding:14px 16px;text-align:center}}
.kpi .n{{font-size:26px;font-weight:800;color:var(--c)}}.kpi .l{{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.6px;margin-top:3px}}
.stack{{height:10px;border-radius:5px;overflow:hidden;display:flex;background:#0e1626;margin-bottom:26px}}.stack span{{height:100%}}
.vuln{{background:var(--card);border:1px solid var(--border);border-left-width:4px;border-radius:12px;padding:16px 18px;margin-bottom:13px}}
.vh{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px}}
.pill{{padding:2px 10px;border-radius:999px;font-size:11px;font-weight:800;color:#0a0e14}}
.vt{{font-weight:700;font-size:15px;flex:1}}.cvss{{font-size:11px;color:var(--dim);border:1px solid var(--border);border-radius:6px;padding:1px 8px}}
.cat{{font-size:11px;color:var(--faint)}}
.desc{{color:#c5cde0;margin:4px 0 8px}}.kv{{font-size:13px;margin:3px 0}}.kv b{{color:var(--dim);font-weight:600;margin-right:6px}}
.ev{{font-family:var(--mono);font-size:12px;background:#0a1120;border:1px solid var(--border);border-radius:8px;padding:8px 10px;margin:8px 0;color:#9fb0c9;overflow-x:auto}}
.rem{{margin-top:8px;font-size:13px}}.rem b{{color:#3ddb87}}
.cmd{{font-family:var(--mono);font-size:12px;background:#06140c;border:1px solid rgba(61,219,135,.25);border-radius:7px;padding:7px 10px;margin-top:5px;color:#8ef0bd;overflow-x:auto}}
.refs{{margin-top:8px;font-size:12px}}.refs a{{color:#7aa2ff;text-decoration:none;margin-right:8px}}
.empty{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:30px;text-align:center;color:var(--dim)}}
.foot{{color:var(--faint);text-align:center;margin-top:28px;font-size:12px}}
</style></head><body>
<header><div class="wrap"><h1>🛡️ <span class="g">AI Security Analysis</span></h1>
<div class="sub">{len(findings)} findings · model {MODEL} · {time.strftime('%Y-%m-%d %H:%M:%S')}</div></div></header>
<div class="wrap">
<div class="grid">{cards}</div>
<div class="stack">{bar}</div>
{''.join(items) if findings else '<div class="empty">No findings were produced from the current logs.</div>'}
<div class="foot">Generated by ScamDroid AI · evidence-backed findings only</div>
</div></body></html>"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(HTML_FILE, "w") as fh:
        fh.write(doc)
    print(f"✅ HTML report → {HTML_FILE}")


def main():
    chunks = read_and_chunk_log(LOG_FILE_PATH)
    if not chunks:
        print("❌ No log data to analyse. Run a scan first.")
        return
    print(f"📊 Analysing {len(chunks)} log chunk(s) with {MODEL}...")
    all_findings: list[dict] = []
    for i, chunk in enumerate(chunks, 1):
        print(f"🔍 chunk {i}/{len(chunks)}")
        result = query_with_retry(chunk, i)  # ← now actually sends the chunk
        if result and "choices" in result:
            content = result["choices"][0]["message"]["content"]
            found = parse_findings(content)
            all_findings.extend(found)
            print(f"   → {len(found)} finding(s)")
            time.sleep(REQUEST_DELAY)
        else:
            print(f"   ⚠️ chunk {i} failed")

    all_findings = dedup(all_findings)
    counts = {s: sum(1 for f in all_findings if f["severity"] == s) for s in SEV_ORDER}
    print(f"\n📄 {len(all_findings)} unique findings "
          f"(C:{counts['Critical']} H:{counts['High']} M:{counts['Medium']} "
          f"L:{counts['Low']} I:{counts['Info']})")
    write_text_report(all_findings)
    write_html_report(all_findings)


if __name__ == "__main__":
    main()
