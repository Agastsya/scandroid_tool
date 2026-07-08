"""VAPT pipeline — load surface, confirm each vuln class, report.

Given a validated recon surface (or an ad-hoc URL/list), it runs the right
confirming scanner for each in-scope vuln class, optionally a nuclei DAST pass
across every parameterized URL, and writes the confirmation-first report.
"""
from __future__ import annotations

from datetime import datetime

from scamrecon import ui
from . import config, loader, payloads, scanners, report
from .config import PROFILES, OUTPUT_DIR
from .vstate import VaptState

# class -> scanner fn
SCANNERS = {
    "sqli": scanners.scan_sqli,
    "xss": scanners.scan_xss,
    "lfi": scanners.scan_lfi,
    "ssti": scanners.scan_ssti,
    "rce": scanners.scan_rce,
    "ssrf": scanners.scan_ssrf,
    "redirect": scanners.scan_redirect,
    "crlf": scanners.scan_crlf,
}
NEEDS_PAYLOADS = {"lfi", "rce", "xss", "sqli"}


def run(*, recon=None, url=None, url_file=None, profile_name="standard",
        max_minutes: int = 120, label: str | None = None) -> VaptState:
    from scamrecon import runner
    profile = PROFILES.get(profile_name, PROFILES["standard"])
    label = label or recon or url or url_file or "target"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # derive a clean output-dir name (strip paths, keep it short & readable)
    import re
    base = str(label).rstrip("/").split("/")[-1]
    short = re.sub(r"[^a-zA-Z0-9._-]", "_", base)[:40] or "target"
    outdir = OUTPUT_DIR / f"{short}_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)
    st = VaptState(target_label=str(label), outdir=outdir, profile_name=profile_name)

    # Global wall-clock budget + fresh tool ledger.
    runner.reset_ledger()
    runner.set_deadline(max_minutes * 60)

    ui.rule(f"VAPT · {label} · profile {profile_name} · ≤{max_minutes}m")
    TOTAL = 6

    # 1) Load the test surface
    ui.phase_header(1, TOTAL, "Load & validate test surface")
    if recon:
        loader.from_recon(recon, st, profile.classes)
    elif url:
        loader.from_urls([url], st, profile.classes)
        st.live_targets = [url]
    elif url_file:
        from scamrecon import runner
        loader.from_urls(runner.read_lines(__import__("pathlib").Path(url_file)), st, profile.classes)
    loader.validate_live(st)

    # 2) Expand surface — hidden-parameter discovery (fights false negatives).
    #    ALWAYS runs when the loaded surface is thin, even if the profile would
    #    normally skip it — otherwise a domain with few archived URLs yields
    #    "no targets in scope" and the scanners have nothing to test.
    surface_total = sum(len(v) for v in st.surface.values())
    ui.phase_header(2, TOTAL, "Expand attack surface (parameter & endpoint discovery)")
    if profile.expand_params or surface_total < 25:
        if surface_total < 25 and not profile.expand_params:
            ui.info(f"surface is thin ({surface_total} URLs) — forcing param/endpoint discovery")
        try:
            scanners.expand_surface(st, profile)
        except Exception as e:  # noqa: BLE001
            ui.err(f"surface expansion error: {e}")
    else:
        ui.step("param discovery disabled for this profile")

    # 3) Prepare payloads
    ui.phase_header(3, TOTAL, "Prepare payloads")
    payloads.ensure_all([c for c in profile.classes if c in NEEDS_PAYLOADS])

    # 4) Confirm each vuln class (zero-false-positive scanners)
    rem = runner.remaining()
    ui.phase_header(4, TOTAL, f"Confirm vulnerabilities (zero-false-positive scanners)"
                    + (f"  [~{int(rem//60)}m left]" if rem is not None else ""))
    for vclass in profile.classes:
        if runner.expired():
            ui.warn(f"time budget reached — skipping remaining classes at '{vclass}'")
            runner.record("(pipeline)", "skipped", f"classes from '{vclass}' skipped: time budget")
            break
        targets = st.surface.get(vclass, [])
        fn = SCANNERS.get(vclass)
        if not fn:
            continue
        if not targets and vclass not in ("ssrf", "ssti"):
            ui.step(f"{vclass}: no targets in scope — skipped")
            continue
        ui.info(f"── {vclass.upper()} ──")
        try:
            fn(st, targets, profile)
        except Exception as e:  # noqa: BLE001
            ui.err(f"{vclass} scanner error: {e}")

    # 5) Broad confirmation passes — nuclei host-level tags + DAST + CORS
    ui.phase_header(5, TOTAL, "Broad confirmation (nuclei host-level + DAST + CORS)")
    if profile.nuclei_tags and not runner.expired():
        try:
            scanners.scan_nuclei_tags(st, profile)
        except Exception as e:  # noqa: BLE001
            ui.err(f"nuclei tags error: {e}")
    if st.live_targets and not runner.expired():
        try:
            scanners.scan_cors(st, st.live_targets)
        except Exception as e:  # noqa: BLE001
            ui.err(f"cors error: {e}")
    if profile.use_broad_scanners and st.live_targets and not runner.expired():
        try:
            scanners.scan_tls(st, st.live_targets)
        except Exception as e:  # noqa: BLE001
            ui.err(f"tls error: {e}")
    if profile.nuclei_dast and not runner.expired():
        all_param = sorted({u for urls in st.surface.values() for u in urls})
        if all_param:
            try:
                scanners.scan_nuclei_dast(st, all_param, profile)
            except Exception as e:  # noqa: BLE001
                ui.err(f"nuclei dast error: {e}")

    # 6) Report
    runner.set_deadline(None)  # lift budget for report generation
    st.finished = datetime.now()
    ui.phase_header(6, TOTAL, "Report")
    arts = report.build(st)
    _summary(st, arts)
    return st


def _summary(st: VaptState, arts: dict) -> None:
    sev = st.severity_counts()
    ui.rule("VAPT COMPLETE")
    ui.summary_table("Confirmed Vulnerabilities", [
        ("CONFIRMED (proven)", len(st.confirmed)),
        ("Reportable (conf+firm)", len(st.reportable)),
        ("Critical", sev["critical"]), ("High", sev["high"]), ("Medium", sev["medium"]),
        ("Needs manual review", len(st.review)),
    ], accent="red" if (sev["critical"] or sev["high"]) else "green")

    if st.reportable:
        ui.data_table("Findings", ["Sev", "Conf", "Class", "Vulnerability", "URL"],
                      [[v.severity, v.confidence, v.vclass, v.name[:34], v.url[:52]]
                       for v in st.reportable], accent="red", max_rows=30)
    else:
        ui.good("No vulnerabilities confirmed — clean on the tested surface (validated result).")

    # surface any tools that stalled or were skipped so nothing is silent
    from scamrecon import runner
    led = runner.ledger()
    problems = [(t, e) for t, e in led.items()
                if t != "(pipeline)" and (e.get("timeout") or e.get("error")
                or (e.get("skipped") and not e.get("ok")))]
    if problems:
        ui.warn(f"{len(problems)} tool(s) timed out / skipped (see Tool Coverage in the report):")
        for t, e in problems[:12]:
            state = "timeout" if e.get("timeout") else "failed" if e.get("error") else "skipped"
            ui.step(f"{t:20} {state}  {e.get('detail','')}")

    if arts.get("pdf"):
        ui.good(f"PDF report  : {arts['pdf']}")
    ui.good(f"HTML report : {arts['html']}")
    ui.good(f"JSON data   : {arts['json']}")
    ui.good(f"Duration    : {st.duration}")
