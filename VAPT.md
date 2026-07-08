# ScamVapt — Confirmation-First VAPT Framework

A vulnerability assessment engine that consumes **ScamRecon**'s validated attack
surface and confirms **only real, tool-proven** critical/high vulnerabilities.
Built for **Kali, Parrot, and macOS (Apple Silicon)**.

**Core principle — zero false positives.** A finding is reported only when a
tool *proves* it: sqlmap identifies the DBMS/injection, dalfox verifies the XSS
fires, an LFI payload returns a real `/etc/passwd` signature, commix executes a
command, SSTImap escalates to code execution, Interactsh receives an out-of-band
SSRF callback. Unproven heuristics are quarantined under "Needs Manual Review",
never counted as vulnerabilities.

**No false negatives, either.** Before testing, the surface is *widened* — hidden
parameters (arjun), archived URLs (gau), and live crawl (katana) — then every
class is tested with nested double-passes. Cast a wide net; report only proof.

---

## Quick start

```bash
python3 vapt.py --install                              # install & verify the toolchain
python3 vapt.py -d example.com                          # FULL: recon (find subdomains) → VAPT
python3 vapt.py -d example.com -p deep --max-time 120   # deep recon + deep VAPT, ≤2h
python3 vapt.py --from-recon recon_output              # skip recon, reuse a recon run
python3 vapt.py -u "https://site/p?id=1"               # single URL
python3 vapt.py -l urls.txt                            # URL list
python3 vapt.py                                        # interactive menu
```

Outputs land in `vapt_output/<target>_<ts>/` — open `report.html` or `report.pdf`.

### `-d domain` — the full chain (what you usually want)

Given just a domain, ScamVapt runs the **whole thing** end to end:

1. **Stage 1 — Recon:** discovers subdomains (passive: subfinder/amass/crt.sh/…;
   active: puredns brute + permutations), resolves + drops dead names, validates
   live hosts (httpx + curl), and harvests URLs/parameters.
2. **Stage 2 — VAPT:** runs the confirmation-first scanners over every live host
   and parameter discovered.

The `--max-time` budget (default 120 min) is split ~40% recon / ~60% VAPT, and
neither stage can run past it. Profile maps: `fast`→quick recon, `standard`→
standard recon, `deep`→deep recon.

## Pipeline

| # | Phase | What it does |
|---|-------|--------------|
| 1 | Load & validate surface | consumes recon `validated_vectors` + live hosts; httpx pre-flight |
| 2 | Expand surface | arjun hidden params + gau archived URLs + katana crawl (kills false negatives) |
| 3 | Prepare payloads | best public LFI/XSS/SQLi/RCE lists (bundled offline fallback) |
| 4 | Confirm each class | SQLi, XSS, LFI, SSTI, RCE, SSRF, redirect, CRLF — proof-gated |
| 5 | Broad confirmation | nuclei host-level (cve/exposure/misconfig) + nuclei DAST + CORS + TLS |
| 6 | Report | HTML + PDF + JSON + Markdown |

### Confirmation methods (per class)

- **SQLi** — sqlmap (detect → 2nd pass enumerates DBs) + ghauri corroboration.
- **XSS** — Gxss/kxss reflection pre-filter → dalfox verification → XSStrike 2nd pass.
- **LFI** — payload injection with `/etc/passwd` signature match + nuclei LFI templates.
- **SSTI** — nuclei SSTI templates + SSTImap (escalates to RCE for hard proof).
- **RCE** — commix confirmed command execution.
- **SSRF** — Interactsh OOB callback (irrefutable) + nuclei SSRF templates.
- **Open redirect** — off-site `Location` header confirmation with a canary host.
- **CRLF** — crlfuzz. **CORS** — corsy / origin-reflection+credentials probe.
- **TLS** — testssl.sh / sslscan (deep profile).
- **Broad** — nuclei host-level tags + DAST fuzzing-templates (matched = confirmed).

### Confidence grading

- **confirmed** — a tool proved exploitability → counted as a vulnerability.
- **firm** — strong signal from a reliable detector → reported, clearly labelled.
- **tentative** — heuristic only → "Needs Manual Review", never a headline vuln.

## Reports

Each confirmed finding shows: severity + CWE, target, parameter, payload,
evidence, **numbered steps to reproduce**, a copy-paste **PoC**, remediation, and
references — in a polished SVG report (`report.html`) and a printable
`report.pdf`, plus `report.json` and `summary.md`.

## Scan profiles

- **fast** — SQLi+XSS+LFI+redirect, confirmed critical/high, tight budgets.
- **standard** — all 8 classes, param discovery, nuclei tags+DAST, nested passes.
- **deep** — sqlmap L5/R3, full discovery, broad scanners (nikto/wapiti/testssl), double passes.

## Toolchain (37 tools)

`python3 vapt.py --status` lists them. Core: sqlmap, dalfox, nuclei, httpx.
Confirmers & helpers: ghauri, commix, SSTImap, crlfuzz, corsy, interactsh-client,
Gxss, XSStrike, arjun, gau, katana, ffuf, feroxbuster, testssl.sh, sslscan,
trufflehog, gitleaks, wafw00f, jaeles, oralyzer, uro, gf, qsreplace + more.
Missing tools are skipped gracefully — never fatal.

## Notes

- **Authorization required:** only test targets you own or are explicitly
  permitted to assess. This tool actively sends exploit payloads.
