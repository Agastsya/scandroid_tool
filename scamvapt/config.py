"""VAPT configuration — tool registry, payload sources, scan profiles.

Reuses ScamRecon's platform detection and Tool dataclass so installation
behaves identically across Kali / Parrot / macOS. The toolset here is the
confirm-the-vuln layer: injection, XSS, LFI, RCE, SSRF and misconfig testers
plus the plumbing (gf/qsreplace/uro) that shapes a clean, deduped test surface.
"""
from __future__ import annotations

from pathlib import Path

# Reuse the recon framework's platform + Tool primitives (single source of truth)
from scamrecon.config import Tool, PLATFORM, go_bin_dir, BASE_DIR  # noqa: F401

OUTPUT_DIR = BASE_DIR / "vapt_output"
PAYLOAD_DIR = BASE_DIR / "payloads"
for _d in (OUTPUT_DIR, PAYLOAD_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────
#  Tool registry — the confirmation-first VAPT toolchain (25+)
# ─────────────────────────────────────────────────────────────
TOOLS: dict[str, Tool] = {
    # ── SQL injection ──────────────────────────────────────────
    "sqlmap":  Tool("sqlmap", "SQL injection — detect & confirm (the gold standard)",
                    brew="sqlmap", apt="sqlmap", pip="sqlmap"),
    "ghauri":  Tool("ghauri", "Fast SQLi confirmer (boolean/time/error/union)",
                    pip="ghauri", optional=True),
    "sqlninja": Tool("sqlninja", "MSSQL injection exploitation (Perl)",
                     apt="sqlninja", optional=True),

    # ── XSS ────────────────────────────────────────────────────
    "dalfox":  Tool("dalfox", "XSS scanner that verifies reflection/DOM execution",
                    brew="dalfox", go="github.com/hahwul/dalfox/v2@latest"),
    "kxss":    Tool("kxss", "Reflected-parameter finder (pairs with dalfox)",
                    go="github.com/Emoun/kxss@latest", optional=True),
    "Gxss":    Tool("Gxss", "Reflection checker — pre-filters params for dalfox",
                    go="github.com/KathanP19/Gxss@latest", optional=True),
    "xsstrike": Tool("xsstrike", "XSS with context analysis + fuzzing (2nd XSS confirmer)",
                    git="https://github.com/s0md3v/XSStrike", optional=True),

    # ── Command injection / RCE / SSTI ─────────────────────────
    "commix":  Tool("commix", "Command-injection detection & exploitation",
                    brew="commix", apt="commix", git="https://github.com/commixproject/commix", optional=True),
    "sstimap": Tool("sstimap", "Server-Side Template Injection → RCE confirmer",
                    git="https://github.com/vladko312/SSTImap", optional=True),

    # ── CRLF / header injection ────────────────────────────────
    "crlfuzz": Tool("crlfuzz", "CRLF injection scanner (low false-positive)",
                    go="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest", optional=True),

    # ── CORS / misconfig corroboration ─────────────────────────
    "corsy":   Tool("corsy", "CORS misconfiguration scanner",
                    git="https://github.com/s0md3v/Corsy", optional=True),
    "jaeles":  Tool("jaeles", "Signature-based web scanner (extra corroboration)",
                    go="github.com/jaeles-project/jaeles@latest", optional=True),

    # ── Template scanner + DAST engine ─────────────────────────
    "nuclei":  Tool("nuclei", "Template + DAST fuzzing engine (critical/high focus)",
                    brew="nuclei", go="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),

    # ── OOB / blind confirmation ───────────────────────────────
    "interactsh-client": Tool("interactsh-client", "Out-of-band interaction server (blind SSRF/RCE proof)",
                    brew="interactsh-client",
                    go="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", optional=True),

    # ── Parameter discovery (widen coverage before testing) ────
    "arjun":   Tool("arjun", "HTTP parameter discovery (finds hidden testable params)",
                    pip="arjun", optional=True),
    "paramspider": Tool("paramspider", "Mine parameter URLs from web archives",
                    pip="paramspider", optional=True),

    # ── Surface shaping utilities ──────────────────────────────
    "gf":        Tool("gf", "grep patterns for sqli/xss/lfi/ssrf/redirect URLs",
                      go="github.com/tomnomnom/gf@latest", optional=True),
    "qsreplace": Tool("qsreplace", "Replace query-string values with payloads",
                      go="github.com/tomnomnom/qsreplace@latest", optional=True),
    "uro":       Tool("uro", "Dedup/normalize URL lists (shrinks test surface)",
                      pip="uro", optional=True),
    "httpx":     Tool("httpx", "Confirm targets are live before testing",
                      brew="httpx", go="github.com/projectdiscovery/httpx/cmd/httpx@latest"),

    # ── Broad web scanners (secondary corroboration) ───────────
    "wapiti":  Tool("wapiti", "Black-box web vuln scanner (SQLi/XSS/LFI/…)",
                    pip="wapiti3", optional=True),
    "nikto":   Tool("nikto", "Web server misconfiguration scanner",
                    brew="nikto", apt="nikto", optional=True),
    "wpscan":  Tool("wpscan", "WordPress vulnerability scanner",
                    apt="wpscan", optional=True),

    # ── TLS / transport security ───────────────────────────────
    "testssl":  Tool("testssl.sh", "Deep TLS/SSL configuration & vuln tester",
                     brew="testssl", apt="testssl.sh", git="https://github.com/drwetter/testssl.sh", optional=True),
    "sslscan":  Tool("sslscan", "Fast SSL/TLS cipher & protocol scanner",
                     brew="sslscan", apt="sslscan", optional=True),

    # ── Content / endpoint discovery (widen surface) ───────────
    "ffuf":     Tool("ffuf", "Fast web fuzzer (content & vhost discovery)",
                     brew="ffuf", go="github.com/ffuf/ffuf/v2@latest", optional=True),
    "feroxbuster": Tool("feroxbuster", "Recursive content discovery (Rust)",
                     brew="feroxbuster", optional=True),
    "katana":   Tool("katana", "JS-aware crawler to expand endpoints from a URL",
                     brew="katana", go="github.com/projectdiscovery/katana/cmd/katana@latest", optional=True),
    "gau":      Tool("gau", "Archived URLs (Wayback/CommonCrawl) to expand surface",
                     go="github.com/lc/gau/v2/cmd/gau@latest", optional=True),
    "waybackurls": Tool("waybackurls", "Wayback URL harvester",
                     go="github.com/tomnomnom/waybackurls@latest", optional=True),

    # ── Secrets / info leakage ─────────────────────────────────
    "trufflehog": Tool("trufflehog", "Verified secret scanning (keys/tokens with live check)",
                     brew="trufflehog", git="https://github.com/trufflesecurity/trufflehog", optional=True),
    "gitleaks":  Tool("gitleaks", "Detect secrets & exposed .git",
                     brew="gitleaks", optional=True),

    # ── Recon-adjacent confirmers ──────────────────────────────
    "wafw00f":   Tool("wafw00f", "WAF fingerprint (tunes payloads / avoids noise)",
                     pip="wafw00f", optional=True),
    "oralyzer":  Tool("oralyzer", "Open-redirect analyzer (secondary confirmer)",
                     git="https://github.com/r0075h3ll/Oralyzer", optional=True),
    "smuggler":  Tool("smuggler", "HTTP request-smuggling detector",
                     git="https://github.com/defparam/smuggler", optional=True),

    # ── Utility ────────────────────────────────────────────────
    "anew":    Tool("anew", "Append-only dedup for pipelines",
                    go="github.com/tomnomnom/anew@latest", optional=True),
    "dirsearch": Tool("dirsearch", "Web path scanner (content discovery)",
                    pip="dirsearch", optional=True),
}

CORE_TOOLS = [n for n, t in TOOLS.items() if not t.optional]
OPTIONAL_TOOLS = [n for n, t in TOOLS.items() if t.optional]


# ─────────────────────────────────────────────────────────────
#  Payload wordlist sources (downloaded + bundled fallback)
# ─────────────────────────────────────────────────────────────
# Best-in-class public payload lists (SecLists + PayloadsAllTheThings). Merged &
# deduped; bundled fallbacks in scamvapt/data/ cover the offline case.
PAYLOAD_SOURCES = {
    "lfi": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Linux-files.txt",
    ],
    "xss": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt",
        "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
    ],
    "sqli": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/quick-SQLi.txt",
        "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/Generic_SQLI.txt",
    ],
    "rce": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt",
        "https://raw.githubusercontent.com/payloadbox/command-injection-payload-list/master/command-injection-payload-list.txt",
    ],
}


# ─────────────────────────────────────────────────────────────
#  Vulnerability classes → which scanners confirm them
# ─────────────────────────────────────────────────────────────
# Mirrors the recon triage class names so we can consume its buckets directly.
CLASS_ALIASES = {
    "sqli": ["sqli", "sql"],
    "xss": ["xss"],
    "lfi": ["lfi", "path", "traversal", "file"],
    "rce": ["rce", "cmd", "command"],
    "ssti": ["ssti", "template"],
    "ssrf": ["ssrf"],
    "redirect": ["redirect", "open redirect", "openredirect"],
    "crlf": ["crlf"],
}

# nuclei template locations (fuzzing-templates powers the DAST pass)
import os as _os
NUCLEI_TEMPLATES = Path(_os.path.expanduser("~/nuclei-templates"))
FUZZING_TEMPLATES = Path(_os.path.expanduser("~/fuzzing-templates"))


# ─────────────────────────────────────────────────────────────
#  Scan profiles
# ─────────────────────────────────────────────────────────────
from dataclasses import dataclass


@dataclass
class Profile:
    name: str
    description: str
    classes: list          # which vuln classes to test
    sqlmap_level: int
    sqlmap_risk: int
    nuclei_severity: str
    nuclei_dast: bool
    nuclei_tags: bool           # host-level exposures/cve/misconfig pass
    expand_params: bool         # arjun/gf hidden-parameter discovery
    double_pass: bool           # enumerate/enrich after a confirmed hit
    max_targets_per_class: int
    use_broad_scanners: bool


ALL_CLASSES = ["sqli", "xss", "lfi", "rce", "ssti", "ssrf", "redirect", "crlf"]

PROFILES = {
    "fast": Profile(
        "fast", "Confirmed critical/high, tight budgets. SQLi+XSS+LFI+redirect + param discovery + nuclei host-pass.",
        classes=["sqli", "xss", "lfi", "redirect"],
        sqlmap_level=1, sqlmap_risk=1, nuclei_severity="critical,high",
        nuclei_dast=False, nuclei_tags=True, expand_params=True, double_pass=False,
        max_targets_per_class=50, use_broad_scanners=False),
    "standard": Profile(
        "standard", "All classes, sqlmap L2/R2, param discovery, nuclei tags+DAST, nested passes.",
        classes=ALL_CLASSES,
        sqlmap_level=2, sqlmap_risk=2, nuclei_severity="critical,high",
        nuclei_dast=True, nuclei_tags=True, expand_params=True, double_pass=True,
        max_targets_per_class=150, use_broad_scanners=False),
    "deep": Profile(
        "deep", "Exhaustive: sqlmap L5/R3, full param discovery, tags+DAST, broad scanners, double passes.",
        classes=ALL_CLASSES,
        sqlmap_level=5, sqlmap_risk=3, nuclei_severity="critical,high,medium",
        nuclei_dast=True, nuclei_tags=True, expand_params=True, double_pass=True,
        max_targets_per_class=500, use_broad_scanners=True),
}
