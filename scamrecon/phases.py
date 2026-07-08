"""Recon phases — the actual work, one function per stage of the methodology.

The flow mirrors how a bug-bounty recon pipeline is built in the field
(subfinder/amass -> puredns brute -> dnsx resolve -> httpx probe -> naabu/nmap
-> katana/gau crawl -> nuclei/subzy), with every step feeding the shared
ReconState and writing raw artifacts to disk for auditability.

Each phase degrades gracefully: if a tool isn't installed it is skipped, never
fatal. Only the domain you pass is enumerated — keep it authorized.
"""
from __future__ import annotations

import json
import re

import requests

from . import config, ui, runner, wordlists
from .config import (TOOLS, PROFILES, RESOLVERS_FILE, RESOLVERS_TRUSTED_FILE,
                     SUBS_WORDLIST, PERMUTATION_WORDLIST)
from .state import ReconState, LiveHost, Finding


def _trusted_resolvers() -> str | None:
    """Reliable resolvers for resolution/validation (never the huge public list)."""
    path = wordlists.ensure_trusted_resolvers()
    return path if path else None


def _brute_resolvers() -> str | None:
    """Large validated list for high-volume brute-force (puredns filters these).

    Falls back to the trusted list if the big list is missing or empty (e.g. a
    failed download) — never hand a tool an empty resolver file, which hangs it.
    """
    if RESOLVERS_FILE.exists() and RESOLVERS_FILE.stat().st_size > 50:
        return str(RESOLVERS_FILE)
    return _trusted_resolvers()


# ─────────────────────────────────────────────────────────────
#  Phase 1 — Passive subdomain enumeration
# ─────────────────────────────────────────────────────────────
def passive_subdomains(st: ReconState) -> None:
    d = st.dir("01_subdomains")
    domain = st.target

    # Each source is an independent (tool_label, callable→hosts) task. They all
    # hit different APIs/binaries, so we run them concurrently and merge once —
    # wall-clock ≈ the slowest source instead of the sum of all sources.
    sources: list = []
    if TOOLS["subfinder"].installed():
        sources.append(("subfinder", lambda: runner.run(
            ["subfinder", "-d", domain, "-all", "-silent"], timeout=180).lines))
    if TOOLS["assetfinder"].installed():
        sources.append(("assetfinder", lambda: runner.run(
            ["assetfinder", "--subs-only", domain], timeout=120).lines))
    if TOOLS["amass"].installed():
        sources.append(("amass", lambda: [re.split(r"\s+", l)[0] for l in runner.run(
            ["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=300).lines]))
    if TOOLS["findomain"].installed():
        sources.append(("findomain", lambda: runner.run(
            ["findomain", "-t", domain, "-q"], timeout=120).lines))
    sources.append(("crt.sh", lambda: _crtsh(domain)))
    if TOOLS["github-subdomains"].installed() and _env_token():
        sources.append(("github", lambda: runner.run(
            ["github-subdomains", "-d", domain, "-t", _env_token()], timeout=120).lines))
    if TOOLS["cero"].installed():
        sources.append(("cero", lambda: runner.run(["cero", domain], timeout=60).lines))

    ui.step(f"querying {len(sources)} passive sources in parallel...")

    def _run(entry):
        label, fn = entry
        return label, (fn() or [])

    found: set[str] = set()
    for res in runner.parallel_map(_run, sources, workers=len(sources) or 1):
        if not res:
            continue
        label, items = res
        clean = {s.lower().strip(". ") for s in items
                 if s and (s == domain or s.endswith("." + domain))}
        st.sources[label] = st.sources.get(label, 0) + len(clean)
        found.update(clean)
        ui.result_count(label, len(clean), "subdomains")

    st.subdomains.update(found)
    st.subdomains.add(domain)
    runner.write_lines(d / "passive_subdomains.txt", st.subdomains)
    ui.good(f"passive total: {len(st.subdomains):,} unique subdomains")


# ─────────────────────────────────────────────────────────────
#  Phase 1b — Recursive / nested enumeration (go deeper per subdomain)
# ─────────────────────────────────────────────────────────────
# Subdomains whose names suggest they host more infrastructure underneath.
RECURSE_KEYWORDS = ("api", "dev", "staging", "stage", "test", "qa", "uat", "internal",
                    "corp", "vpn", "admin", "portal", "gateway", "gw", "app", "cloud",
                    "svc", "service", "mail", "auth", "sso", "id", "console")


def recursive_enum(st: ReconState, profile, max_seeds: int = 15) -> None:
    """Treat interesting discovered subdomains as new roots and dig one level deeper.

    e.g. after finding api.example.com we re-run passive discovery on it to catch
    v1.api.example.com, internal.api.example.com, etc. Bounded by max_seeds so it
    can't explode combinatorially.
    """
    d = st.dir("01_subdomains")
    domain = st.target
    seeds = [s for s in st.subdomains if s != domain
             and any(k in s.split(".")[0] for k in RECURSE_KEYWORDS)]
    # rank: deepest / most-keyword-rich first, then cap
    seeds = sorted(set(seeds), key=lambda s: (-sum(k in s for k in RECURSE_KEYWORDS), len(s)))[:max_seeds]
    if not seeds:
        ui.step("no high-value seeds for recursive enumeration")
        return

    ui.step(f"recursive enum on {len(seeds)} high-value seeds "
            f"({', '.join(seeds[:5])}{'...' if len(seeds) > 5 else ''})")
    before = len(st.subdomains)
    new: set[str] = set()
    for seed in seeds:
        if TOOLS["subfinder"].installed():
            r = runner.run(["subfinder", "-d", seed, "-all", "-recursive", "-silent"], timeout=90)
            new.update(s.lower() for s in r.lines if s.endswith("." + domain))
        new.update(_crtsh(seed))
        if TOOLS["cero"].installed():
            r = runner.run(["cero", seed], timeout=40)
            new.update(s.lower().lstrip("*.") for s in r.lines if s.endswith("." + domain))

    st.subdomains.update(new)
    st.sources["recursive"] = st.sources.get("recursive", 0) + (len(st.subdomains) - before)
    runner.write_lines(d / "recursive_subdomains.txt", new)
    ui.good(f"recursive enumeration added {len(st.subdomains) - before:,} deeper subdomains")


def _crtsh(domain: str) -> list[str]:
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
        if r.status_code != 200:
            return []
        out: set[str] = set()
        for row in r.json():
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain):
                    out.add(name)
        return sorted(out)
    except Exception:
        return []


def _env_token() -> str:
    import os
    return os.environ.get("GITHUB_TOKEN", "")


# ─────────────────────────────────────────────────────────────
#  Phase 2 — Active DNS brute-force + permutations
# ─────────────────────────────────────────────────────────────
def active_bruteforce(st: ReconState, profile) -> None:
    d = st.dir("01_subdomains")
    domain = st.target
    resolvers = _brute_resolvers()
    wl = str(SUBS_WORDLIST) if SUBS_WORDLIST.exists() else None

    if not wl:
        ui.warn("no subdomain wordlist — skipping brute-force")
        return

    brute_out = d / "bruteforce.txt"
    before = len(st.subdomains)

    if TOOLS["puredns"].installed() and resolvers:
        ui.step("puredns bruteforce (wildcard-aware)...")
        cmd = ["puredns", "bruteforce", wl, domain, "-r", resolvers,
               "-w", str(brute_out), "-q"]
        r = runner.stream(cmd, timeout=1200, quiet=True)
        st.subdomains.update(runner.read_lines(brute_out))
    elif TOOLS["shuffledns"].installed() and resolvers:
        ui.step("shuffledns bruteforce...")
        cmd = ["shuffledns", "-d", domain, "-w", wl, "-r", resolvers,
               "-mode", "bruteforce", "-o", str(brute_out), "-silent"]
        runner.stream(cmd, timeout=1200, quiet=True)
        st.subdomains.update(runner.read_lines(brute_out))
    elif TOOLS["dnsx"].installed():
        ui.step("dnsx bruteforce (fallback)...")
        cmd = ["dnsx", "-d", domain, "-w", wl, "-silent", "-o", str(brute_out)]
        if resolvers:
            cmd += ["-r", resolvers]
        runner.stream(cmd, timeout=1200, quiet=True)
        st.subdomains.update(runner.read_lines(brute_out))
    else:
        ui.warn("no brute-force tool available (puredns/shuffledns/dnsx)")

    ui.good(f"brute-force added {len(st.subdomains) - before:,} new subdomains")

    if profile.do_permutations:
        _permutations(st, d, _trusted_resolvers())


def _permutations(st: ReconState, d, resolvers) -> None:
    if not st.subdomains:
        return
    known = runner.write_lines(d / "known_for_perm.txt", st.subdomains)
    perms_raw = d / "permutations_raw.txt"
    before = len(st.subdomains)

    if TOOLS["gotator"].installed() and PERMUTATION_WORDLIST.exists():
        ui.step("gotator generating permutations...")
        r = runner.run(["gotator", "-sub", str(known), "-perm", str(PERMUTATION_WORDLIST),
                        "-depth", "1", "-numbers", "5", "-mindup", "-adv", "-md"], timeout=300)
        runner.write_lines(perms_raw, r.lines)
    elif TOOLS["alterx"].installed():
        ui.step("alterx generating permutations...")
        r = runner.run(["alterx", "-l", str(known), "-silent"], timeout=300)
        runner.write_lines(perms_raw, r.lines)
    else:
        return

    # resolve the generated permutations
    if perms_raw.exists() and resolvers:
        resolved_perms = d / "permutations_resolved.txt"
        if TOOLS["puredns"].installed():
            runner.stream(["puredns", "resolve", str(perms_raw), "-r", resolvers,
                           "-w", str(resolved_perms), "-q"], timeout=600, quiet=True)
        elif TOOLS["dnsx"].installed():
            runner.stream(["dnsx", "-l", str(perms_raw), "-r", resolvers,
                           "-silent", "-o", str(resolved_perms)], timeout=600, quiet=True)
        st.subdomains.update(runner.read_lines(resolved_perms))
        ui.good(f"permutations added {len(st.subdomains) - before:,} new subdomains")


# ─────────────────────────────────────────────────────────────
#  Phase 3 — DNS resolution & validation
# ─────────────────────────────────────────────────────────────
def resolve_all(st: ReconState, profile) -> None:
    d = st.dir("02_resolved")
    subs_file = runner.write_lines(d / "all_subdomains.txt", st.subdomains)
    resolvers = _trusted_resolvers()   # validation must use reliable resolvers

    if not TOOLS["dnsx"].installed():
        ui.warn("dnsx not installed — validating via curl/requests fallback")
        _dns_fallback(st, d)
        _apply_dns_filter(st, d)
        return

    json_out = d / "dnsx.json"
    cmd = ["dnsx", "-l", str(subs_file), "-a", "-aaaa", "-cname",
           "-json", "-silent", "-t", str(min(profile.resolve_threads, 100)), "-o", str(json_out)]
    if resolvers:
        cmd += ["-r", resolvers]
    runner.stream(cmd, timeout=900, quiet=True)

    for line in runner.read_lines(json_out):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        host = rec.get("host", "").lower()
        if not host:
            continue
        st.resolved[host] = {
            "a": rec.get("a", []),
            "aaaa": rec.get("aaaa", []),
            "cname": rec.get("cname", []),
        }
    # Safety net: if dnsx returned nothing but we clearly have subdomains,
    # validate directly with dnspython so we never silently report zero.
    if not st.resolved and st.subdomains:
        ui.warn("dnsx returned no records — falling back to dnspython resolution")
        _dns_fallback(st, d)

    _apply_dns_filter(st, d)


def _apply_dns_filter(st: ReconState, d) -> None:
    """HARD FILTER: drop everything that doesn't resolve to a DNS record.

    Brute-force + permutations generate huge numbers of names that don't exist;
    carrying them wastes time in every later phase and clutters the report with
    dead hosts. Keep only real (resolving) subdomains; the rest are archived to
    unresolved_dropped.txt for the record but dropped from the run.
    """
    if st.discovered:      # already filtered (avoid double-apply)
        return
    st.discovered = len(st.subdomains)
    resolved_set = set(st.resolved.keys()) | {st.target}
    st.unresolved = {s for s in st.subdomains if s not in resolved_set}
    st.subdomains = {s for s in st.subdomains if s in resolved_set}

    runner.write_lines(d / "resolved.txt", st.resolved.keys())
    if st.unresolved:
        runner.write_lines(d / "unresolved_dropped.txt", st.unresolved)
    ui.good(f"resolved {len(st.resolved):,}/{st.discovered:,} subdomains "
            f"(dropped {len(st.unresolved):,} dead/non-existent names)")


def _dns_fallback(st: ReconState, d) -> None:
    """Resolve every subdomain with dnspython — reliable, no external tool."""
    import concurrent.futures
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=True)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.lifetime = 5.0
    resolver.timeout = 5.0

    def resolve_one(host: str):
        rec = {"a": [], "aaaa": [], "cname": []}
        got = False
        for rtype, key in (("A", "a"), ("AAAA", "aaaa"), ("CNAME", "cname")):
            try:
                ans = resolver.resolve(host, rtype)
                rec[key] = [r.to_text() for r in ans]
                got = True
            except Exception:
                continue
        return (host, rec) if got else None

    hosts = sorted(st.subdomains)
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        for res in ex.map(resolve_one, hosts):
            if res:
                st.resolved[res[0]] = res[1]


# ─────────────────────────────────────────────────────────────
#  Phase 4 — Live host probing (httpx) + validation
# ─────────────────────────────────────────────────────────────
def probe_live(st: ReconState) -> None:
    d = st.dir("03_live")
    hosts = st.resolved_hosts or sorted(st.subdomains)
    if not hosts:
        ui.warn("no hosts to probe")
        return
    hosts_file = runner.write_lines(d / "resolve_input.txt", hosts)

    if not TOOLS["httpx"].installed():
        ui.warn("httpx not installed — falling back to curl validation")
        _curl_fallback(st, hosts, d)
        return

    json_out = d / "httpx.json"
    cmd = ["httpx", "-l", str(hosts_file), "-json", "-o", str(json_out),
           "-status-code", "-title", "-tech-detect", "-web-server", "-ip",
           "-cdn", "-location", "-content-length", "-follow-redirects",
           "-threads", "150", "-silent"]
    runner.stream(cmd, timeout=900, quiet=True)

    for line in runner.read_lines(json_out):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        url = rec.get("url", "")
        if not url:
            continue
        tech = rec.get("tech", []) or []
        lh = LiveHost(
            url=url,
            host=rec.get("input", rec.get("host", "")),
            status=int(rec.get("status_code", 0) or 0),
            title=(rec.get("title", "") or "")[:120],
            webserver=rec.get("webserver", "") or "",
            tech=tech,
            ip=(rec.get("a", [""]) or [""])[0] if rec.get("a") else rec.get("host", ""),
            cdn=rec.get("cdn_name", "") or "",
            content_length=int(rec.get("content_length", 0) or 0),
            scheme=rec.get("scheme", ""),
        )
        st.live[url] = lh
        for t in tech:
            st.technologies[t] = st.technologies.get(t, 0) + 1

    runner.write_lines(d / "live_urls.txt", st.live.keys())
    ui.good(f"{len(st.live):,} live web services confirmed (validated by httpx)")
    if st.technologies:
        top = sorted(st.technologies.items(), key=lambda x: -x[1])[:8]
        ui.step("top tech: " + ", ".join(f"{k}({v})" for k, v in top))


def _curl_fallback(st: ReconState, hosts: list[str], d) -> None:
    import concurrent.futures
    live = {}

    def check(host: str):
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                r = requests.head(url, timeout=6, allow_redirects=True)
                return url, r.status_code
            except Exception:
                try:
                    r = requests.get(url, timeout=6, stream=True)
                    return url, r.status_code
                except Exception:
                    continue
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        for res in ex.map(check, hosts):
            if res:
                url, sc = res
                live[url] = LiveHost(url=url, host=url.split("//")[1], status=sc)
    st.live.update(live)
    runner.write_lines(d / "live_urls.txt", st.live.keys())
    ui.good(f"{len(st.live):,} live hosts confirmed (curl/requests fallback)")


# ─────────────────────────────────────────────────────────────
#  Phase 5 — Port scanning (naabu) + NSE service/vuln detection
# ─────────────────────────────────────────────────────────────
def _ports_reliable(host: str) -> bool:
    """Detect networks that answer SYN-ACK for every port (ISP/captive-portal/
    proxy interception). We probe 3 ports that are almost certainly closed; if
    2+ "connect", the network is lying and port results can't be trusted."""
    import socket
    import random
    opened = 0
    for port in random.sample(range(40000, 61000), 3):
        s = socket.socket()
        s.settimeout(4)
        try:
            s.connect((host, port))
            opened += 1
        except Exception:
            pass
        finally:
            s.close()
    return opened < 2


def port_scan(st: ReconState, profile) -> None:
    d = st.dir("04_ports")
    # scan the resolved hosts (by name) — naabu resolves them
    targets = st.resolved_hosts or sorted({lh.host for lh in st.live.values()})
    if not targets:
        ui.warn("no hosts for port scan")
        return
    tfile = runner.write_lines(d / "portscan_input.txt", targets)

    if not TOOLS["naabu"].installed():
        ui.warn("naabu not installed — skipping port discovery")
        return

    # Sanity-gate: if the local network intercepts TCP, every port looks open.
    # Report honestly instead of dumping false positives.
    probe_host = targets[0]
    if not _ports_reliable(probe_host):
        st.ports_unreliable = True
        ui.err("network interception detected — TCP connects succeed to closed ports.")
        ui.warn("Port scan SKIPPED to avoid false positives. Re-run on a clean "
                "network / VPN (or your Kali/Parrot box) for accurate port data.")
        (d / "WARNING_network_interception.txt").write_text(
            "Port scanning was skipped: the local network answered TCP handshakes "
            "for random closed ports on " + probe_host + ", which means a middlebox "
            "(ISP/captive portal/transparent proxy) is intercepting connections. "
            "Every port would falsely appear open. Re-run from a network without "
            "such interception (home/VPN/cloud box) for trustworthy results.\n")
        return

    naabu_out = d / "naabu.txt"
    port_arg = {"top-100": ["-top-ports", "100"],
                "top-1000": ["-top-ports", "1000"],
                "full": ["-p", "-"]}.get(profile.naabu_ports, ["-top-ports", "1000"])
    # -verify re-confirms every "open" port with a full TCP handshake (kills the
    # false positives connect-scans pick up behind load balancers / SYN-proxies).
    # High concurrency + a bounded wall-clock so it can never stall the pipeline.
    cmd = ["naabu", "-list", str(tfile), *port_arg, "-verify", "-c", "100",
           "-rate", "2000", "-silent", "-o", str(naabu_out)]
    naabu_budget = 300 if profile.naabu_ports != "full" else 900
    ui.step(f"naabu scanning ({profile.naabu_ports}, verified, ≤{naabu_budget//60}m)...")
    runner.stream(cmd, timeout=naabu_budget, quiet=True)

    for line in runner.read_lines(naabu_out):
        if ":" in line:
            host, _, port = line.rpartition(":")
            try:
                st.ports.setdefault(host, []).append(int(port))
            except ValueError:
                pass
    total_ports = sum(len(v) for v in st.ports.values())
    ui.good(f"{total_ports:,} open ports across {len(st.ports):,} hosts")

    if profile.do_nse and TOOLS["nmap"].installed() and st.ports:
        _nmap_nse(st, d, profile)


# Curated, SAFE NSE script sets. These *detect* weaknesses (including
# DoS-susceptibility) without launching actual DoS/exploit traffic — we
# deliberately avoid nmap's aggressive `dos` category, which performs attacks.
#
# FAST = the high-signal subset used by the standard profile (single pass) — it
# omits the notoriously slow scripts (ssl-enum-ciphers, http-enum) so the phase
# can't stall. FULL = the exhaustive set, used only by the `deep` profile.
NSE_SCRIPTS_FAST = ",".join([
    "banner", "vulners",
    "http-title", "http-headers", "http-methods", "http-server-header",
    "http-security-headers", "http-git", "http-open-redirect", "http-shellshock",
    "http-slowloris-check",
    "ssl-cert", "ssl-dh-params", "ssl-ccs-injection",
    "dns-recursion", "dns-zone-transfer",
    "ftp-anon", "smtp-open-relay",
])
NSE_SCRIPTS_FULL = ",".join([
    "default", "banner", "vulners",
    "http-title", "http-headers", "http-methods", "http-server-header",
    "http-security-headers", "http-cors", "http-robots.txt", "http-git",
    "http-enum", "http-auth-finder", "http-cookie-flags", "http-csrf",
    "http-open-redirect", "http-dombased-xss", "http-shellshock",
    "http-slowloris-check",
    "ssl-cert", "ssl-enum-ciphers", "ssl-dh-params", "ssl-ccs-injection",
    "ssl-known-key", "sslv2", "tls-alpn", "tls-nextprotoneg",
    "dns-nsid", "dns-recursion", "dns-cache-snoop", "dns-zone-transfer",
    "ftp-anon", "smtp-open-relay", "ssh-auth-methods", "ssh2-enum-algos",
])


def _nmap_nse(st: ReconState, d, profile) -> None:
    """Parallel nmap NSE with a hard per-host time cap so it can never stall.

    `--host-timeout` guarantees nmap abandons any slow host and returns what it
    has, `--script-timeout` bounds each script, and hosts are scanned
    concurrently. Standard runs a single fast pass; `deep` runs the exhaustive
    two-pass script set. This is the fix for the pipeline "hanging on step 7".
    """
    deep = profile.name == "deep"
    scripts = NSE_SCRIPTS_FULL if deep else NSE_SCRIPTS_FAST
    host_cap = 30 if deep else 15
    host_timeout = "240s" if deep else "90s"
    script_timeout = "40s" if deep else "20s"
    ranked = sorted(st.ports.items(), key=lambda x: -len(x[1]))[:host_cap]
    ui.step(f"nmap NSE on {len(ranked)} hosts in parallel "
            f"({'deep 2-pass' if deep else 'fast single-pass'}, ≤{host_timeout}/host)...")

    def _scan_host(item):
        host, ports = item
        ports_csv = ",".join(str(p) for p in sorted(set(ports)))
        xml2 = d / f"nmap_nse_{host}.xml"
        txt2 = d / f"nmap_nse_{host}.txt"
        # single combined pass: version detection + curated scripts, hard-capped
        runner.run(["nmap", "-sV", "-Pn", "-T4", "--script", scripts,
                    "--host-timeout", host_timeout, "--script-timeout", script_timeout,
                    "--max-retries", "2", "-p", ports_csv, host,
                    "-oX", str(xml2), "-oN", str(txt2)],
                   timeout=int(host_timeout[:-1]) + 60)
        deep_svc = _parse_nmap_xml(xml2)
        if deep:  # deep gets a 2nd -sC fingerprint pass for extra coverage
            xml1 = d / f"nmap_sv_{host}.xml"
            runner.run(["nmap", "-sV", "-sC", "-Pn", "-T4", "--host-timeout", host_timeout,
                        "-p", ports_csv, host, "-oX", str(xml1)], timeout=300)
            for svc in (_parse_nmap_xml(xml1) or []):
                if not any(s["port"] == svc["port"] for s in deep_svc):
                    deep_svc.append(svc)
        return host, deep_svc

    workers = min(10 if deep else 12, len(ranked) or 1)
    for res in runner.parallel_map(_scan_host, ranked, workers=workers):
        if not res:
            continue
        host, deep_svc = res
        if deep_svc:
            st.nmap_services[host] = deep_svc
            _nse_findings(st, host, deep_svc)

    svc_count = sum(len(v) for v in st.nmap_services.values())
    ui.good(f"nmap identified {svc_count:,} services; NSE run on {len(ranked)} hosts")


def _nse_findings(st: ReconState, host: str, services: list[dict]) -> None:
    """Promote interesting NSE script results (CVEs, weak TLS, DoS-vuln) to findings."""
    interesting = {
        "vulners": ("high", "CVEs matched to service version"),
        "ssl-dh-params": ("medium", "Weak Diffie-Hellman parameters (Logjam)"),
        "ssl-ccs-injection": ("high", "OpenSSL CCS injection"),
        "http-slowloris-check": ("medium", "Slowloris DoS susceptibility"),
        "http-shellshock": ("critical", "Shellshock"),
        "http-open-redirect": ("low", "Open redirect"),
        "dns-zone-transfer": ("high", "DNS zone transfer (AXFR) allowed"),
        "dns-recursion": ("low", "Open DNS recursion"),
        "smtp-open-relay": ("high", "Open SMTP relay"),
        "ftp-anon": ("medium", "Anonymous FTP allowed"),
        "http-git": ("medium", "Exposed .git directory"),
    }
    for svc in services:
        for sid, output in (svc.get("scripts") or {}).items():
            if sid in interesting and output and "ERROR" not in output.upper():
                # zone-transfer / vulners only matter when they actually returned data
                sev, name = interesting[sid]
                if sid == "vulners" and "CVE" not in output.upper():
                    continue
                if sid == "dns-zone-transfer" and "failed" in output.lower():
                    continue
                st.findings.append(Finding(
                    template=f"nse:{sid}", name=f"{name} ({svc.get('service','')})",
                    severity=sev, host=f"{host}:{svc['port']}",
                    matched=output.strip().splitlines()[0][:160] if output.strip() else "",
                    tags="nmap,nse",
                ))


def _parse_nmap_xml(path) -> list[dict]:
    if not path.exists():
        return []
    import xml.etree.ElementTree as ET
    services = []
    try:
        root = ET.parse(path).getroot()
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            scripts = {s.get("id"): (s.get("output") or "")[:400] for s in port.findall("script")}
            services.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": svc.get("name") if svc is not None else "",
                "product": svc.get("product") if svc is not None else "",
                "version": svc.get("version") if svc is not None else "",
                "scripts": scripts,
            })
    except Exception:
        pass
    return services


# ─────────────────────────────────────────────────────────────
#  Phase 6 — URL / endpoint discovery (crawl + passive archives)
# ─────────────────────────────────────────────────────────────
def crawl_urls(st: ReconState, profile) -> None:
    d = st.dir("05_urls")
    if not st.live:
        ui.warn("no live hosts to crawl")
        return
    live_file = runner.write_lines(d / "crawl_input.txt", st.live.keys())
    domain = st.target

    # gau / waybackurls (passive archives) and katana/gospider (active crawl) are
    # independent — run them concurrently and merge the URL sets afterwards.
    tasks: list = []
    if TOOLS["gau"].installed():
        tasks.append(("gau", lambda: runner.run(
            ["gau", "--subs", "--threads", "5", domain], timeout=300).lines))
    if TOOLS["waybackurls"].installed():
        tasks.append(("waybackurls", lambda: runner.run(
            ["waybackurls", domain], timeout=180).lines))
    if TOOLS["katana"].installed():
        subset = list(st.live.keys())[: profile.max_crawl_hosts] or list(st.live.keys())
        subset_file = runner.write_lines(d / "katana_input.txt", subset)
        katana_out = d / "katana.txt"

        def _katana():
            runner.stream(["katana", "-list", str(subset_file), "-d", "3", "-jc", "-kf", "all",
                           "-c", "15", "-silent", "-o", str(katana_out)], timeout=900, quiet=True)
            return runner.read_lines(katana_out)
        tasks.append(("katana", _katana))
    elif TOOLS["gospider"].installed():
        tasks.append(("gospider", lambda: [l.split()[-1] for l in runner.run(
            ["gospider", "-S", str(live_file), "-d", "2", "-c", "10", "--other-source", "-q"],
            timeout=600).lines if "http" in l]))

    if tasks:
        ui.step(f"crawling with {len(tasks)} source(s) in parallel...")

        def _run(entry):
            label, fn = entry
            return label, (fn() or [])
        for res in runner.parallel_map(_run, tasks, workers=len(tasks)):
            if not res:
                continue
            label, urls = res
            st.urls.update(urls)
            ui.result_count(label, len(urls), "urls")

    st.urls = {u for u in st.urls if domain in u}
    runner.write_lines(d / "all_urls.txt", st.urls)
    params = {u for u in st.urls if "?" in u and "=" in u}
    runner.write_lines(d / "param_urls.txt", params)
    ui.good(f"{len(st.urls):,} unique URLs ({len(params):,} with parameters)")


# ─────────────────────────────────────────────────────────────
#  Phase 6b — URL triage: flag likely-attackable endpoints
# ─────────────────────────────────────────────────────────────
# Parameter names commonly associated with each vulnerability class. This is a
# recon triage aid — it points the analyst at the highest-value URLs so the
# report is "easy to attack" without the tool itself performing any exploitation.
ATTACK_PARAMS = {
    "Open Redirect": ["url", "redirect", "next", "return", "returnurl", "return_url",
                      "redirect_uri", "redirect_url", "continue", "dest", "destination",
                      "redir", "target", "goto", "out", "view", "link", "forward"],
    "SSRF": ["url", "uri", "path", "dest", "domain", "callback", "feed", "host",
             "site", "port", "to", "out", "proxy", "fetch", "resource", "load"],
    "LFI / Path Traversal": ["file", "path", "include", "page", "template", "doc",
                             "document", "folder", "root", "pg", "style", "pdf", "read"],
    "SQLi (candidate)": ["id", "select", "report", "search", "category", "cat",
                         "order", "sort", "user", "uid", "pid", "item", "query", "q"],
    "SSTI / RCE (candidate)": ["cmd", "exec", "command", "run", "ping", "query",
                               "code", "func", "callback", "template"],
    "IDOR (candidate)": ["id", "user_id", "uid", "account", "number", "no", "doc",
                         "order_id", "invoice", "file_id", "profile"],
}


def triage_urls(st: ReconState) -> None:
    from urllib.parse import urlparse, parse_qs
    d = st.dir("05_urls")
    buckets: dict[str, set] = {k: set() for k in ATTACK_PARAMS}
    for url in st.urls:
        if "?" not in url:
            continue
        params = {p.lower() for p in parse_qs(urlparse(url).query)}
        if not params:
            continue
        for cls, names in ATTACK_PARAMS.items():
            if params & set(names):
                buckets[cls].add(url)
    st.interesting = {k: sorted(v) for k, v in buckets.items() if v}
    total = sum(len(v) for v in st.interesting.values())
    for cls, urls in st.interesting.items():
        runner.write_lines(d / f"interesting_{cls.split()[0].lower()}.txt", urls)
    if total:
        ui.good(f"triage: {total:,} parameterized URLs flagged across "
                f"{len(st.interesting)} attack classes")
        for cls, urls in sorted(st.interesting.items(), key=lambda x: -len(x[1])):
            ui.step(f"{cls:26} {len(urls):>5,} candidate URLs")
    else:
        ui.step("no parameterized URLs to triage")


# ─────────────────────────────────────────────────────────────
#  Phase — Independent validation (curl): prune dead hosts & vectors
# ─────────────────────────────────────────────────────────────
def _http_probe(url: str, timeout: int = 8) -> dict | None:
    """One independent request (separate from httpx). Returns evidence or None.

    A host counts as reachable if the TCP+TLS+HTTP round-trip actually returns a
    status line — connection errors, DNS failures and timeouts are treated as
    dead and pruned. This is the 'confirm with curl' pass the report relies on.
    """
    import time as _t
    headers = {"User-Agent": "Mozilla/5.0 (compatible; ScamRecon/1.0; validation)"}
    for method in ("head", "get"):
        try:
            t0 = _t.time()
            r = requests.request(method, url, timeout=timeout, allow_redirects=True,
                                 headers=headers, stream=True, verify=False)
            ms = int((_t.time() - t0) * 1000)
            # HEAD sometimes 405s; fall through to GET for a real body-bearing check
            if method == "head" and r.status_code in (405, 501):
                continue
            return {"status": r.status_code, "final_url": r.url, "ms": ms}
        except requests.exceptions.RequestException:
            continue
    return None


def validate_assets(st: ReconState, profile) -> None:
    """Curl every live host and every attack vector; drop anything that's dead."""
    import concurrent.futures
    import warnings
    warnings.filterwarnings("ignore")  # silence InsecureRequestWarning for verify=False
    d = st.dir("10_validated")

    # 1) Validate live hosts ------------------------------------------------
    urls = list(st.live.keys())
    if urls:
        ui.step(f"curl-validating {len(urls):,} live host(s)...")
        kept, dropped = {}, []
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
            futs = {ex.submit(_http_probe, u): u for u in urls}
            for fut in concurrent.futures.as_completed(futs):
                u = futs[fut]
                ev = fut.result()
                if ev:
                    lh = st.live[u]
                    lh.validated = True
                    lh.final_url = ev["final_url"]
                    lh.response_ms = ev["ms"]
                    if ev["status"]:
                        lh.status = ev["status"]
                    kept[u] = lh
                else:
                    dropped.append(u)
        st.live = kept
        runner.write_lines(d / "validated_live.txt", st.live.keys())
        if dropped:
            runner.write_lines(d / "dropped_dead_hosts.txt", dropped)
        ui.good(f"{len(kept):,} hosts confirmed reachable; pruned {len(dropped):,} dead")

    # 2) Validate attack vectors (parameterized URLs) -----------------------
    if st.interesting:
        total_vec = sum(len(v) for v in st.interesting.values())
        # cap to keep it bounded on large surfaces
        cap = 300 if profile.name != "deep" else 1500
        ui.step(f"curl-validating attack vectors (up to {cap} of {total_vec:,})...")
        validated: dict[str, list] = {}
        checked = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
            for cls, vlist in st.interesting.items():
                sample = vlist[:cap]
                futs = {ex.submit(_http_probe, u, 6): u for u in sample}
                alive = []
                for fut in concurrent.futures.as_completed(futs):
                    checked += 1
                    ev = fut.result()
                    # keep vectors that respond with a real HTTP status (not dead)
                    if ev and ev["status"] and ev["status"] < 600:
                        alive.append(futs[fut])
                if alive:
                    validated[cls] = sorted(alive)
                    runner.write_lines(d / f"vectors_{cls.split()[0].lower()}.txt", alive)
        st.validated_vectors = validated
        kept_vec = sum(len(v) for v in validated.values())
        ui.good(f"{kept_vec:,} live attack vectors confirmed (of {checked:,} checked)")
        for cls, v in sorted(validated.items(), key=lambda x: -len(x[1])):
            ui.step(f"{cls:26} {len(v):>5,} reachable")
    # rebuild technologies map from surviving hosts
    st.technologies = {}
    for lh in st.live.values():
        for t in lh.tech:
            st.technologies[t] = st.technologies.get(t, 0) + 1


# ─────────────────────────────────────────────────────────────
#  Phase 7 — JavaScript file discovery
# ─────────────────────────────────────────────────────────────
def javascript_recon(st: ReconState) -> None:
    d = st.dir("06_javascript")
    # JS files already surface in crawled URLs; also run subjs for coverage
    js = {u for u in st.urls if u.split("?")[0].endswith(".js")}
    if TOOLS["subjs"].installed() and st.live:
        live_file = d / "subjs_input.txt"
        runner.write_lines(live_file, st.live.keys())
        r = runner.run(["subjs", "-i", str(live_file)], timeout=300)
        js.update(l for l in r.lines if l.startswith("http"))
    st.js_files.update(js)
    runner.write_lines(d / "js_files.txt", st.js_files)
    ui.good(f"{len(st.js_files):,} JavaScript files discovered")


# ─────────────────────────────────────────────────────────────
#  Phase 8 — Nuclei recon (exposures / misconfig / tech / CVEs)
# ─────────────────────────────────────────────────────────────
def nuclei_recon(st: ReconState, profile) -> None:
    d = st.dir("07_nuclei")
    if not st.live:
        ui.warn("no live hosts for nuclei")
        return
    if not TOOLS["nuclei"].installed():
        ui.warn("nuclei not installed — skipping")
        return
    live_file = runner.write_lines(d / "nuclei_input.txt", st.live.keys())
    json_out = d / "nuclei.jsonl"

    # Scale the wall-clock budget to the number of hosts so a slow/rate-limited
    # target (e.g. behind Cloudflare) can't hang the run indefinitely.
    n_hosts = len(st.live)
    budget = min(1800, max(300, n_hosts * 30))

    # recon-focused: no intrusive/dos/fuzzing tags. Bounded per-request timeout,
    # retries, and concurrency keep it responsive even against rate-limiters.
    cmd = ["nuclei", "-l", str(live_file), "-jsonl", "-o", str(json_out),
           "-severity", profile.nuclei_severity,
           "-tags", "exposure,misconfig,tech,takeover,cve,ssl,default-login,config,panel,disclosure",
           "-exclude-tags", "intrusive,dos,fuzz,brute-force",
           "-timeout", "8", "-retries", "1", "-concurrency", "25",
           "-rate-limit", "150", "-disable-update-check",
           "-silent", "-stats", "-no-color"]
    ui.step(f"nuclei scanning (recon templates, budget {budget//60}m for {n_hosts} host(s))...")
    r = runner.stream(cmd, timeout=budget, quiet=True)
    if r.stderr and "timeout" in r.stderr:
        ui.warn("nuclei hit its time budget — partial results captured")

    for line in runner.read_lines(json_out):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        info = rec.get("info", {})
        st.findings.append(Finding(
            template=rec.get("template-id", ""),
            name=info.get("name", ""),
            severity=(info.get("severity", "info") or "info").lower(),
            host=rec.get("host", rec.get("matched-at", "")),
            matched=rec.get("matched-at", ""),
            tags=",".join(info.get("tags", []) if isinstance(info.get("tags"), list) else []),
        ))
    counts = st.severity_counts()
    ui.good(f"nuclei: {len(st.findings):,} findings "
            f"(C:{counts['critical']} H:{counts['high']} M:{counts['medium']} "
            f"L:{counts['low']} I:{counts['info']})")


# ─────────────────────────────────────────────────────────────
#  Phase 9 — Subdomain takeover detection
# ─────────────────────────────────────────────────────────────
def takeover_check(st: ReconState) -> None:
    d = st.dir("08_takeover")
    subs = runner.write_lines(d / "takeover_input.txt", st.resolved.keys() or st.subdomains)
    if TOOLS["subzy"].installed():
        ui.step("subzy takeover check...")
        r = runner.run(["subzy", "run", "--targets", str(subs), "--hide_fails"], timeout=600)
        for line in r.lines:
            if "VULNERABLE" in line.upper() or "[ VULNERABLE ]" in line:
                st.takeovers.append({"host": line, "source": "subzy"})
    # nuclei takeover findings also count
    for f in st.findings:
        if "takeover" in f.tags:
            st.takeovers.append({"host": f.host, "source": "nuclei", "template": f.template})
    if st.takeovers:
        ui.warn(f"{len(st.takeovers)} potential subdomain takeover(s) — verify manually")
    else:
        ui.good("no subdomain takeovers detected")


# ─────────────────────────────────────────────────────────────
#  Phase 10 — Screenshots
# ─────────────────────────────────────────────────────────────
def screenshots(st: ReconState) -> None:
    d = st.dir("09_screenshots")
    if not st.live or not TOOLS["gowitness"].installed():
        if not TOOLS["gowitness"].installed():
            ui.warn("gowitness not installed — skipping screenshots")
        return
    live_file = runner.write_lines(d / "shot_input.txt", st.live.keys())
    st.screenshots_dir = d
    ui.step("gowitness capturing screenshots...")
    # gowitness v3 syntax, fall back to v2
    r = runner.run(["gowitness", "scan", "file", "-f", str(live_file),
                    "--screenshot-path", str(d), "--write-none"], timeout=900)
    if r.skipped or (not r.ok and "unknown command" in r.stderr.lower()):
        runner.run(["gowitness", "file", "-f", str(live_file), "-P", str(d)], timeout=900)
    shots = list(d.glob("*.png")) + list(d.glob("*.jpeg"))
    ui.good(f"{len(shots)} screenshots captured")


# ─────────────────────────────────────────────────────────────
#  Phase 0 — OSINT (ASN / whois) — quick context
# ─────────────────────────────────────────────────────────────
def osint(st: ReconState) -> None:
    d = st.dir("00_osint")
    if TOOLS["asnmap"].installed():
        r = runner.run(["asnmap", "-d", st.target, "-silent"], timeout=60)
        st.asn_info = r.lines
        runner.write_lines(d / "asn_ranges.txt", r.lines)
        if r.lines:
            ui.result_count("asnmap", len(r.lines), "CIDR ranges")
    import shutil
    if shutil.which("whois"):
        r = runner.run(["whois", st.target], timeout=30)
        st.whois = "\n".join(r.lines[:80])
        (d / "whois.txt").write_text(st.whois)
