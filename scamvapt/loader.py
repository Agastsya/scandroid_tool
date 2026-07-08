"""Load a test surface for VAPT — from a recon run, a URL, or a file.

The primary path is `--from-recon`: it reads ScamRecon's `report.json`, takes the
already **validated** attack vectors (grouped by likely class) and live hosts, and
maps them onto VAPT's vuln classes. Because recon already curl-validated these,
we start from a clean, reachable surface instead of guessing.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from scamrecon import ui, runner
from .config import CLASS_ALIASES
from .vstate import VaptState


def _class_of(recon_label: str) -> str | None:
    low = recon_label.lower()
    for vclass, aliases in CLASS_ALIASES.items():
        if any(a in low for a in aliases):
            return vclass
    return None


def _find_report_json(path: Path) -> Path | None:
    if path.is_file() and path.name.endswith(".json"):
        return path
    if path.is_dir():
        direct = path / "report.json"
        if direct.exists():
            return direct
        # newest recon_output/<domain>_<ts>/report.json under this dir
        candidates = sorted(path.glob("**/report.json"), key=lambda p: p.stat().st_mtime)
        if candidates:
            return candidates[-1]
    return None


def from_recon(recon_path: str, st: VaptState, classes: list[str]) -> None:
    p = _find_report_json(Path(recon_path))
    if not p:
        ui.err(f"no recon report.json found at {recon_path}")
        return
    st.source_recon = str(p)
    data = json.loads(p.read_text())
    ui.good(f"loaded recon report: {p}  (target: {data.get('target','?')})")

    # Priority-ordered surface: validated vectors FIRST (curl-confirmed, so most
    # likely real → tested first within the per-class cap), then harvested URLs.
    surface: dict[str, list] = {c: [] for c in classes}

    # 1) validated attack vectors (curl-confirmed live) — highest priority
    vectors = data.get("validated_vectors") or data.get("interesting") or {}
    priority_urls: list[str] = []
    for label, urls in vectors.items():
        vclass = _class_of(label)
        if vclass and vclass in surface:
            surface[vclass].extend(urls)              # keep in their labelled class
        priority_urls.extend(urls)                    # and as generic-injection targets
    # every validated vector is also a generic-injection candidate (front of list)
    routed_priority = _route_urls(priority_urls, classes)
    for c in classes:
        if c in _GENERIC_INJECTION:
            surface[c] = list(dict.fromkeys(surface[c] + routed_priority.get(c, [])))

    live = [h["url"] for h in data.get("live_hosts", [])]
    st.live_targets = live

    # 2) FULL parameterized-URL harvest from the recon output dir (lower priority).
    recon_dir = p.parent
    extra_files = [recon_dir / "05_urls" / "param_urls.txt",
                   recon_dir / "05_urls" / "all_urls.txt"]
    extra_files += list((recon_dir / "10_validated").glob("vectors_*.txt")) \
        if (recon_dir / "10_validated").exists() else []
    harvested: list[str] = []
    for f in extra_files:
        if f.exists():
            harvested += [l.strip() for l in f.read_text().splitlines()
                          if l.strip() and "?" in l and "=" in l]
    if harvested:
        routed = _route_urls(sorted(dict.fromkeys(harvested)), classes)
        for c, urls in routed.items():
            existing = surface.get(c, [])
            seen = set(existing)
            surface[c] = existing + [u for u in urls if u not in seen]
        ui.step(f"harvested {len(set(harvested)):,} parameterized URLs from the recon run dir")

    st.surface = {c: v for c, v in surface.items() if v}
    total = sum(len(v) for v in st.surface.values())
    if total:
        ui.good(f"test surface: {total:,} target URLs across {len(st.surface)} classes")
        for c, v in sorted(st.surface.items(), key=lambda x: -len(x[1])):
            ui.step(f"{c:10} {len(v):>5,} target URLs")
    else:
        ui.warn("no parameterized attack vectors in recon output — "
                "will still run host-level scans (nuclei) on live hosts")


# parameter-name → likely vuln class heuristics (shared by both loaders)
PARAM_HINTS = {
    "sqli": {"id", "pid", "cat", "category", "user", "uid", "order", "sort", "select", "where", "search", "q", "query", "item", "product", "page_id", "news"},
    "lfi": {"file", "path", "page", "doc", "document", "include", "template", "load", "read", "dir", "download", "folder", "pg", "style", "view"},
    "redirect": {"url", "next", "redirect", "return", "returnurl", "dest", "destination", "continue", "goto", "target", "r", "redir", "out", "link"},
    "ssrf": {"url", "uri", "host", "site", "domain", "callback", "webhook", "proxy", "fetch", "image_url", "feed", "u", "load", "port"},
    "rce": {"cmd", "exec", "command", "run", "ping", "query", "code", "eval", "system", "do", "func", "option"},
    "xss": {"q", "search", "s", "query", "name", "message", "comment", "keyword", "redirect", "return", "title", "text", "content", "email"},
    "ssti": {"name", "template", "page", "content", "message", "preview", "q"},
    "crlf": {"url", "redirect", "next", "return", "header", "location"},
}


# These scanners inject into EVERY parameter of a URL, so any parameterized URL
# is a valid target regardless of the parameter's name. Param-name hints only
# *prioritize* — they must never *exclude*, or real bugs get skipped.
_GENERIC_INJECTION = {"sqli", "xss", "lfi", "rce", "ssti"}


def _route_urls(urls: list[str], classes: list[str]) -> dict[str, list]:
    """Bucket parameterized URLs into vuln classes, PRESERVING input order.

    Every parameterized URL is testable by the generic-injection scanners
    (SQLi/XSS/LFI/RCE/SSTI) — they try each parameter. Hint-based classes
    (redirect/ssrf/crlf) get name-matched URLs, and if none match they fall back
    to the full parameterized set so nothing is silently skipped. Order is kept
    so callers can pass higher-priority URLs first (they get tested first).
    """
    from urllib.parse import urlparse, parse_qs
    matched: dict[str, list] = {c: [] for c in classes}
    all_param: list[str] = []
    for u in urls:
        if "?" not in u or "=" not in u:
            continue
        params = {p.lower() for p in parse_qs(urlparse(u).query)}
        if not params:
            continue
        all_param.append(u)
        for vclass in classes:
            if params & PARAM_HINTS.get(vclass, set()):
                matched[vclass].append(u)
    surface: dict[str, list] = {}
    for vclass in classes:
        if vclass in _GENERIC_INJECTION:
            surface[vclass] = all_param                      # test every param URL
        elif matched[vclass]:
            surface[vclass] = matched[vclass]                # hint-matched only
        else:
            surface[vclass] = all_param                      # no match → test all
    return surface


def from_urls(urls: list[str], st: VaptState, classes: list[str]) -> None:
    """Route a raw URL list into classes by parameter-name heuristics."""
    from urllib.parse import urlparse
    surface = _route_urls(urls, classes)
    st.surface = {c: list(dict.fromkeys(v)) for c, v in surface.items() if v}
    st.live_targets = sorted({f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in urls})
    total = sum(len(v) for v in st.surface.values())
    ui.good(f"routed {total:,} URLs into {len(st.surface)} vuln classes")


def validate_live(st: VaptState) -> None:
    """Re-confirm targets are live (httpx) right before testing — no stale hosts."""
    from scamvapt.config import TOOLS
    all_urls = set(st.live_targets)
    for v in st.surface.values():
        all_urls.update(v)
    if not all_urls:
        return
    d = st.dir("00_targets")
    infile = runner.write_lines(d / "all_targets.txt", all_urls)
    if not TOOLS["httpx"].installed():
        ui.warn("httpx not installed — skipping pre-flight live check")
        return
    out = d / "live.txt"
    runner.stream(["httpx", "-l", str(infile), "-silent", "-o", str(out),
                   "-threads", "80", "-mc", "200,201,202,204,301,302,307,400,401,403,405,500"],
                  timeout=300, quiet=True)
    live = set(runner.read_lines(out))
    if live:
        # keep only vectors whose base host is confirmed live
        live_bases = {re.sub(r"\?.*$", "", u) for u in live}
        def _ok(u):
            base = re.sub(r"\?.*$", "", u)
            return base in live_bases or u in live
        st.surface = {c: [u for u in urls if _ok(u)] or urls for c, urls in st.surface.items()}
        ui.good(f"pre-flight: {len(live):,} targets confirmed live")
