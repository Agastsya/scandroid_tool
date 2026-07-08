"""Pipeline — chains the phases into one validated recon run and reports.

This is the single "press go" path: given a root domain it discovers every
asset it can, validates each one (DNS + HTTP), enriches (ports, tech, URLs, JS,
nuclei, takeovers), and writes the report. Nothing here needs babysitting.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from . import config, ui, phases, report, wordlists
from .config import PROFILES
from .state import ReconState


def _clean_domain(target: str) -> str:
    target = target.strip()
    target = re.sub(r"^https?://", "", target)
    target = target.split("/")[0].split(":")[0]
    if target.startswith("www."):
        target = target[4:]
    return target.lower()


def run(target: str, profile_name: str = "standard", deep_wordlists: bool = False,
        max_minutes: int = 120) -> ReconState:
    from . import runner
    domain = _clean_domain(target)
    profile = PROFILES.get(profile_name, PROFILES["standard"])

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = config.OUTPUT_DIR / f"{domain}_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)

    st = ReconState(target=domain, outdir=outdir, profile_name=profile_name)

    # Global wall-clock budget: nothing runs past this; the run always reports.
    runner.reset_ledger()
    runner.set_deadline(max_minutes * 60)

    ui.rule(f"TARGET: {domain}  ·  PROFILE: {profile_name}  ·  OUT: {outdir.name}  ·  ≤{max_minutes}m")

    # Prep wordlists (only needed for active phases)
    if profile.do_bruteforce or profile.do_permutations:
        wordlists.ensure_wordlists(deep=deep_wordlists)

    steps = [
        ("OSINT / ASN context", lambda: phases.osint(st)),
        ("Passive subdomain enumeration", lambda: phases.passive_subdomains(st)),
        ("Active brute-force + permutations",
         (lambda: phases.active_bruteforce(st, profile)) if profile.do_bruteforce else None),
        ("Recursive / nested enumeration",
         (lambda: phases.recursive_enum(st, profile)) if profile.do_bruteforce else None),
        ("DNS resolution & validation", lambda: phases.resolve_all(st, profile)),
        ("Live host probing (httpx)", lambda: phases.probe_live(st)),
        ("Port scan + 2-pass NSE" if profile.do_portscan else None,
         (lambda: phases.port_scan(st, profile)) if profile.do_portscan else None),
        ("URL / endpoint discovery" if profile.do_crawl else None,
         (lambda: phases.crawl_urls(st, profile)) if profile.do_crawl else None),
        ("Attack-surface triage" if profile.do_crawl else None,
         (lambda: phases.triage_urls(st)) if profile.do_crawl else None),
        ("Independent validation (curl) — prune dead hosts & vectors",
         lambda: phases.validate_assets(st, profile)),
        ("JavaScript recon" if profile.do_js else None,
         (lambda: phases.javascript_recon(st)) if profile.do_js else None),
        ("Nuclei recon scan" if profile.do_nuclei else None,
         (lambda: phases.nuclei_recon(st, profile)) if profile.do_nuclei else None),
        ("Takeover check + screenshots", lambda: _finalize_phase(st, profile)),
    ]
    active = [(l, f) for l, f in steps if f is not None and l is not None]
    total = len(active) + 1  # +1 for report

    # Phases that must run even when the clock is up so the report stays useful
    # (they only touch already-collected data, they don't launch slow tools).
    ALWAYS = ("DNS resolution", "Independent validation", "Takeover")

    for n, (label, fn) in enumerate(active, 1):
        rem = runner.remaining()
        if runner.expired() and not any(k in label for k in ALWAYS):
            ui.phase_header(n, total, label)
            ui.warn(f"time budget reached — skipping '{label}' (still generating report)")
            runner.record("(pipeline)", "skipped", f"skipped '{label}': time budget")
            continue
        rem_txt = f"  [~{int(rem//60)}m left]" if rem is not None else ""
        ui.phase_header(n, total, f"{label}{rem_txt}")
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — never let one phase kill the run
            ui.err(f"phase '{label}' error: {e}")
            runner.record("(pipeline)", "error", f"phase '{label}': {e}")

    runner.set_deadline(None)  # lift budget for report generation
    st.finished = datetime.now()
    ui.phase_header(total, total, "Report generation")
    artifacts = report.build(st)
    _final_summary(st, artifacts)
    return st


def _finalize_phase(st: ReconState, profile) -> None:
    phases.takeover_check(st)
    if profile.do_screenshots:
        phases.screenshots(st)


def _final_summary(st: ReconState, artifacts: dict) -> None:
    from . import runner
    sev = st.severity_counts()
    ui.rule("RECON COMPLETE")
    ui.summary_table("Assets Discovered", [
        ("Discovered (raw)", f"{st.discovered or len(st.subdomains):,}"),
        ("Resolved (real DNS)", f"{len(st.resolved):,}"),
        ("Dead dropped", f"{len(st.unresolved):,}"),
        ("Live web services", f"{len(st.live):,}"),
        ("Open ports", f"{sum(len(v) for v in st.ports.values()):,}"),
        ("URLs collected", f"{len(st.urls):,}"),
        ("JavaScript files", f"{len(st.js_files):,}"),
        ("Technologies", f"{len(st.technologies):,}"),
    ], accent="green")
    ui.summary_table("Findings", [
        ("Critical", sev["critical"]), ("High", sev["high"]), ("Medium", sev["medium"]),
        ("Low", sev["low"]), ("Info", sev["info"]),
        ("Potential takeovers", len(st.takeovers)),
    ], accent="red" if (sev["critical"] or sev["high"]) else "yellow")

    if st.live:
        ui.data_table("Live Hosts (validated)",
                      ["Status", "URL", "Title", "Tech"],
                      [[h.status, h.url, h.title[:40], ", ".join(h.tech[:3])]
                       for h in sorted(st.live.values(), key=lambda x: x.url)],
                      accent="green", max_rows=20)

    # surface tools that stalled / were skipped so nothing is silently missing
    led = runner.ledger()
    problems = [(t, e) for t, e in led.items()
                if t != "(pipeline)" and (e.get("timeout") or e.get("error")
                or (e.get("skipped") and not e.get("ok")))]
    if problems:
        ui.warn(f"{len(problems)} tool(s) timed out / skipped (see Tool Coverage in the report):")
        for t, e in problems[:12]:
            state = "timeout" if e.get("timeout") else "failed" if e.get("error") else "skipped"
            ui.step(f"{t:18} {state}  {e.get('detail','')}")

    ui.good(f"HTML report : {artifacts['html']}")
    if artifacts.get("pdf"):
        ui.good(f"PDF report  : {artifacts['pdf']}")
    else:
        ui.warn("PDF report  : skipped (pip install reportlab to enable)")
    ui.good(f"JSON data   : {artifacts['json']}")
    ui.good(f"Markdown    : {artifacts['md']}")
    ui.good(f"Duration    : {st.duration}")
