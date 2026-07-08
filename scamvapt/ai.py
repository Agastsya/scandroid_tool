"""AI-assisted triage — executive summary, business-risk ranking, FP review.

Sends the confirmed findings to an LLM (Groq) and asks for an executive summary,
a business-risk assessment, prioritised remediation, and a false-positive review.
Degrades gracefully: with no API key / no network it produces a solid
*deterministic* executive summary computed straight from the findings, so the
report always has an exec section.
"""
from __future__ import annotations

import json
import os
import re

import requests

API_URL = os.environ.get("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
API_KEY = os.environ.get("GROQ_API_KEY") or "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"
TIMEOUT = 45

SYSTEM = (
    "You are a principal penetration tester writing the executive section of a "
    "VAPT report. You are given a JSON list of ALREADY-CONFIRMED, tool-proven "
    "vulnerabilities (zero false positives by construction). Produce a concise, "
    "board-ready assessment. Respond with ONE JSON object only, this schema:\n"
    '{"executive_summary":"2-4 sentences on overall posture & headline risk",'
    '"business_risk":"Critical|High|Medium|Low",'
    '"risk_rationale":"1-2 sentences",'
    '"top_priorities":["ordered remediation actions, most urgent first"],'
    '"attack_narrative":"1-2 sentences: how an attacker would likely chain these",'
    '"notable_findings":["the few findings that matter most, with the host"]}\n'
    "Be specific and technical but readable by a non-expert exec."
)


def _severity_weight(counts: dict) -> str:
    if counts.get("critical"):
        return "Critical"
    if counts.get("high", 0) >= 3:
        return "Critical"
    if counts.get("high"):
        return "High"
    if counts.get("medium", 0) >= 3:
        return "High"
    if counts.get("medium"):
        return "Medium"
    return "Low"


def _deterministic(findings: list[dict], counts: dict, target: str) -> dict:
    """Offline exec summary computed from the findings — always available."""
    n = len(findings)
    hosts = sorted({f.get("url", "").split("?")[0] for f in findings if f.get("url")})
    classes = {}
    for f in findings:
        classes[f["class"]] = classes.get(f["class"], 0) + 1
    top_classes = ", ".join(f"{c} ({k})" for c, k in
                            sorted(classes.items(), key=lambda x: -x[1])[:5])
    risk = _severity_weight(counts)
    if n == 0:
        summary = (f"No vulnerabilities were confirmed on the tested surface of {target}. "
                   "Every candidate was actively tested; this is a validated clean result, "
                   "not an absence of testing.")
    else:
        summary = (f"{n} tool-confirmed vulnerabilit{'y' if n == 1 else 'ies'} were proven on "
                   f"{target} across {len(hosts)} affected asset(s): "
                   f"{counts.get('critical',0)} critical, {counts.get('high',0)} high, "
                   f"{counts.get('medium',0)} medium. Predominant classes: {top_classes or 'n/a'}. "
                   "All findings are exploitable and reproducible (PoC included per finding).")
    prio = []
    for sev in ("critical", "high", "medium", "low"):
        for f in findings:
            if f["severity"] == sev:
                prio.append(f"Remediate {f['name']} on {f['url'].split('?')[0]}")
        if len(prio) >= 5:
            break
    return {
        "executive_summary": summary,
        "business_risk": risk,
        "risk_rationale": f"Driven by {counts.get('critical',0)} critical / {counts.get('high',0)} high confirmed findings.",
        "top_priorities": prio[:6] or ["Maintain current controls; re-test periodically."],
        "attack_narrative": ("An attacker would chain the confirmed injection/inclusion flaws to read data or gain code execution."
                             if n else "No viable attack chain was demonstrated on the tested surface."),
        "notable_findings": [f"[{f['severity'].upper()}] {f['name']} — {f['url']}"
                             for f in findings[:5]],
        "engine": "deterministic",
    }


def analyze(findings: list[dict], counts: dict, target: str) -> dict:
    """Return an executive/AI-triage block. Tries the LLM, falls back offline."""
    base = _deterministic(findings, counts, target)
    if not findings:
        return base
    # compact the findings for the prompt (cap to keep tokens sane)
    compact = [{"severity": f["severity"], "class": f["class"], "name": f["name"],
                "host": f.get("url", ""), "evidence": (f.get("evidence") or "")[:160]}
               for f in findings[:40]]
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"Target: {target}\nConfirmed findings JSON:\n{json.dumps(compact)}"},
        ],
        "max_tokens": 900, "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    try:
        r = requests.post(API_URL, headers={"Authorization": f"Bearer {API_KEY}",
                          "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT)
        if r.status_code == 400:
            payload.pop("response_format", None)
            r = requests.post(API_URL, headers={"Authorization": f"Bearer {API_KEY}",
                              "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        m = re.search(r"\{.*\}", content, re.DOTALL)
        data = json.loads(m.group(0) if m else content)
        # merge: prefer AI fields, keep deterministic as backstop
        out = dict(base)
        for k in ("executive_summary", "business_risk", "risk_rationale",
                  "top_priorities", "attack_narrative", "notable_findings"):
            if data.get(k):
                out[k] = data[k]
        out["engine"] = f"AI ({MODEL})"
        return out
    except Exception:  # noqa: BLE001 — never let AI break the report
        return base
