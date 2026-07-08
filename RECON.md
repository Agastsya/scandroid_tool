# ScamRecon — Professional Reconnaissance Framework

A cross-platform recon engine that discovers the full attack surface of a root
domain **and every subdomain it owns**, validates each asset (DNS + HTTP), and
produces a clean, report-ready output. Built for **Kali, Parrot, and macOS
(Apple Silicon)**.

It chains 25+ best-in-class tools into one "press go" pipeline. Every host in
the final report has been DNS-resolved and HTTP-validated, so the next stage can
trust it without re-checking.

---

## Quick start

```bash
# 1. Install Python deps + the full toolchain (idempotent, safe to re-run)
pip install -r requirements.txt --break-system-packages
python3 recon.py --install

# 2. Run recon
python3 recon.py -d example.com                # standard (recommended)
python3 recon.py -d example.com -p quick       # fast, passive only
python3 recon.py -d example.com -p deep        # everything, large wordlists

# or launch the interactive menu
python3 recon.py
```

Outputs land in `recon_output/<domain>_<timestamp>/` — open `report.html`.

---

## Pipeline (what runs, in order)

| # | Phase | Tools |
|---|-------|-------|
| 0 | OSINT / ASN context | asnmap, whois |
| 1 | Passive subdomain enum | subfinder, amass, assetfinder, findomain, crt.sh, cero (cert SANs), github-subdomains |
| 2 | Active brute + permutations | puredns / shuffledns / dnsx, gotator / alterx / dnsgen |
| 3 | Recursive / nested enum | re-enumerates high-value seeds (api., dev., admin., …) one level deeper |
| 4 | DNS resolution & validation | dnsx (A/AAAA/CNAME) with **trusted resolvers**; dnspython safety-net |
| 5 | Live host probing | httpx (status, title, tech, server, IP, CDN) — curl fallback |
| 6 | Port scan + 2-pass NSE | naabu `-verify`, then nmap **pass 1** `-sV -sC`, **pass 2** deep NSE scripts |
| 7 | URL / endpoint discovery | katana, gau, waybackurls, gospider |
| 8 | Attack-surface triage | classifies parameterized URLs by attack class (redirect/SSRF/LFI/SQLi/IDOR) |
| 9 | JavaScript recon | subjs + crawled `.js` |
| 10 | Nuclei recon scan | nuclei (exposures, misconfig, tech, CVEs, takeovers — no intrusive/fuzz) |
| 11 | Takeover check + screenshots | subzy, gowitness |
| — | Report | validated HTML + JSON + Markdown |

### nmap NSE (pass 2) — what it detects

The deep NSE pass runs a curated, **non-destructive** script set that *detects*
weaknesses without launching attacks (we deliberately avoid nmap's aggressive
`dos` category, which performs real denial-of-service):

- **HTTP:** http-enum, http-headers, http-methods, http-security-headers,
  http-cors, http-git, http-open-redirect, http-shellshock, **http-slowloris-check**
  (DoS-susceptibility detection)
- **TLS/SSL:** ssl-cert, ssl-enum-ciphers, **ssl-dh-params** (Logjam),
  **ssl-ccs-injection**, sslv2
- **DNS:** dns-nsid, dns-recursion, dns-cache-snoop, **dns-zone-transfer** (AXFR)
- **CVEs:** vulners maps detected versions to known CVEs
- Interesting script hits are promoted into the report's Findings table.

### Network-interception guard

Before port scanning, the tool probes random closed ports. If your network
answers them (ISP/captive-portal/transparent-proxy interception — which makes
*every* port look open), the port scan is **skipped** and the report says so,
instead of dumping false positives. Re-run from a clean network / VPN / cloud box
for trustworthy port data.

### Independent curl-validation

After discovery, a dedicated phase **curls every live host and every attack
vector** (separate from httpx). Anything that fails the TCP+TLS+HTTP round-trip
(DNS failure, refused, timeout) is **pruned** — so the report only ever lists
assets confirmed reachable a second time. Dropped hosts are logged to
`10_validated/dropped_dead_hosts.txt`.

### Reports (HTML + PDF + JSON + Markdown)

- **`report.html`** — polished dark-theme page: SVG logo, KPI cards, an SVG
  severity donut, collapsible sections, curl-validated badge. Self-contained.
- **`report.pdf`** — clean, printable, client-facing PDF (reportlab, zero system
  deps — renders identically on Kali/Parrot/macOS). Donut, severity bar, colored
  findings & host tables.
- **`report.json`** — full machine-readable dataset (consumed by `vapt.py`).
- **`summary.md`** — terse digest for tickets.

Report sections (built for "easy to attack"):
- **Attack Surface Highlights** — prioritized "look here first" list.
- **Validated Attack Vectors** — reachable parameterized URLs grouped by likely
  vuln class (SQLi / LFI / SSRF / redirect / IDOR).
- **Findings** — nuclei + nmap NSE, severity-coded.
- Live hosts, ports, tech stack, all subdomains, discovery provenance.

## Scan profiles

- **quick** — passive discovery + live check + critical/high nuclei. Minutes.
- **standard** — passive + active brute + permutations + ports + NSE + crawl + JS + nuclei. Recommended.
- **deep** — large wordlists, full port range, all severities, screenshots.

## Toolchain

Install status is shown any time with `python3 recon.py --status`. Core tools are
required for good coverage; optional tools (marked `opt`) enrich results and are
skipped gracefully if absent. Missing tools never crash a run.

Install strategy per platform: **macOS** brew → go → pip → git; **Kali/Parrot**
apt → go → pip → git. Go binaries land in `~/go/bin` (add it to your `PATH`).

## Wordlists

Best public subdomain lists are downloaded and **merged + deduped** on first run:
n0kovo (statistical), SecLists top-1M, and bitquark, plus the trickest resolver
set. Cached under `wordlists/`. Refresh anytime with `--refresh-wordlists`
(add `--deep-wordlists` for the large lists).

## Output artifacts

```
recon_output/<domain>_<ts>/
├── report.html          # polished self-contained dark-theme report (SVG donut, KPIs)
├── report.pdf           # printable, client-facing PDF (reportlab)
├── report.json          # full machine-readable dataset for the next stage
├── summary.md           # terse markdown digest
├── 00_osint/  01_subdomains/  02_resolved/  03_live/  04_ports/
├── 05_urls/   06_javascript/  07_nuclei/     08_takeover/  09_screenshots/
└── 10_validated/        # curl-confirmed live hosts & vectors, dropped dead hosts
```

## Notes

- **Authorization:** only scan domains you own or are explicitly permitted to test.
- The recon framework is fully separate from `scanner.py` (the vuln-scan + AI
  patching tool). Recon does no exploitation — discovery and validation only.
