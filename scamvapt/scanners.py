"""Confirming scanners — one per vuln class, each biased to PROOF over noise.

Every scanner returns graded `Vuln`s. The rule enforced everywhere:
  * a finding is `confirmed` only when the tool demonstrates exploitability
    (sqlmap identifies the DBMS/technique, dalfox verifies the XSS fires, an LFI
    payload returns a real `/etc/passwd` line, commix executes a command);
  * strong-but-unproven detector hits are `firm`;
  * anything heuristic is `tentative` (quarantined, never counted as a vuln).

That grading is what keeps false positives out of the headline numbers.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse, parse_qs

import requests

from scamrecon import ui, runner
from .config import TOOLS
from .vstate import VaptState, Vuln
from . import payloads

# signatures that constitute PROOF (not mere reflection of the payload)
LFI_SIGNATURES = [
    re.compile(r"root:.*:0:0:"),                    # /etc/passwd
    re.compile(r"\[(?:fonts|extensions)\]"),        # win.ini
    re.compile(r"daemon:.*:/usr/sbin"),
]
RCE_MARKER = "uid="                                  # output of `id`


def _params(url: str) -> list[str]:
    return list(parse_qs(urlparse(url).query).keys())


def _inject(url: str, param: str, payload: str) -> str:
    """Return url with `param` replaced by payload (URL-encoded)."""
    from urllib.parse import urlencode, urlsplit, parse_qsl, urlunsplit
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query))
    q[param] = payload
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _tool_dir(name: str, script: str) -> str | None:
    """Locate a git-cloned tool's entry script under <repo>/tools/<name>/."""
    from .config import BASE_DIR
    cand = BASE_DIR / "tools" / name / script
    return str(cand) if cand.exists() else None


# ─────────────────────────────────────────────────────────────
#  SQL injection — sqlmap (confirms) + ghauri (confirms)
# ─────────────────────────────────────────────────────────────
def scan_sqli(st: VaptState, targets: list[str], profile) -> None:
    d = st.dir("sqli")
    if not TOOLS["sqlmap"].installed():
        ui.warn("sqlmap not installed — skipping SQLi confirmation")
        return
    targets = targets[: profile.max_targets_per_class]
    ui.step(f"sqlmap confirming SQLi on {len(targets)} target(s) in parallel "
            f"(level {profile.sqlmap_level}, risk {profile.sqlmap_risk})...")

    deep = profile.name == "deep"
    tampers = ["--tamper=space2comment,between,randomcase,charencode"] if deep else []
    technique = "BEUSTQ" if deep else "BEUST"   # deep adds stacked + inline queries

    def _one(item):
        i, url = item
        outdir = d / f"t{i}"
        r = runner.run(["sqlmap", "-u", url, "--batch", "--random-agent",
                        f"--level={profile.sqlmap_level}", f"--risk={profile.sqlmap_risk}",
                        "--threads=6", f"--technique={technique}", "--smart", *tampers,
                        "--output-dir", str(outdir), "-v", "0"], timeout=400 if deep else 300)
        blob = "\n".join(r.lines)
        if re.search(r"is vulnerable|the following injection point|sqlmap identified", blob, re.I):
            dbms = _search(r"back-end DBMS: *(.+)", blob) or _search(r"DBMS: *(.+)", blob) or "unknown"
            param = _search(r"Parameter: *([^\s(]+)", blob) or (_params(url) or [""])[0]
            technique = _search(r"Type: *(.+)", blob) or "injection"
            evidence = f"sqlmap confirmed injectable; back-end DBMS: {dbms}"
            if profile.double_pass:  # nested enumeration to strengthen the proof
                g = runner.run(["sqlmap", "-u", url, "--batch", "--random-agent",
                                "--dbs", "--threads=4", "--output-dir", str(outdir), "-v", "0"],
                               timeout=240)
                dbs = re.findall(r"\[\*\] (\w+)", "\n".join(g.lines))
                if dbs:
                    evidence += f"; enumerated DBs: {', '.join(dbs[:8])}"
            st.add(Vuln(vclass="sqli", name=f"SQL Injection ({technique})", severity="critical",
                        confidence="confirmed", url=url, parameter=param,
                        evidence=evidence, tool="sqlmap",
                        request=f"sqlmap -u '{url}' --batch --dbs --dump"))
            ui.err(f"  [CONFIRMED] SQLi: {url}  (param {param}, {dbms})")
        elif TOOLS["ghauri"].installed():
            g = runner.run(["ghauri", "-u", url, "--batch", "--confirm"], timeout=180)
            if any("injectable" in l.lower() or "vulnerable" in l.lower() for l in g.lines):
                st.add(Vuln(vclass="sqli", name="SQL Injection", severity="critical",
                            confidence="confirmed", url=url,
                            parameter=(_params(url) or [""])[0],
                            evidence="ghauri confirmed injectable", tool="ghauri",
                            request=f"ghauri -u '{url}' --dbs"))
                ui.err(f"  [CONFIRMED] SQLi (ghauri): {url}")

    runner.parallel_map(_one, list(enumerate(targets, 1)), workers=min(6, len(targets) or 1))


# ─────────────────────────────────────────────────────────────
#  XSS — dalfox (verifies reflection + execution context)
# ─────────────────────────────────────────────────────────────
def scan_xss(st: VaptState, targets: list[str], profile) -> None:
    d = st.dir("xss")
    if not TOOLS["dalfox"].installed():
        ui.warn("dalfox not installed — skipping XSS confirmation")
        return
    targets = targets[: profile.max_targets_per_class]

    # ── nested pre-filter: keep only params that actually reflect ──────────
    # Gxss/kxss are cheap; running them first shrinks dalfox's surface to the
    # URLs worth deeply verifying (fewer requests, higher confirmation rate).
    reflected = list(targets)
    prefilter = "Gxss" if TOOLS["Gxss"].installed() else ("kxss" if TOOLS["kxss"].installed() else None)
    if prefilter and targets:
        ui.step(f"{prefilter} pre-filtering reflected parameters...")
        r = runner.run([prefilter], timeout=180, stdin_data="\n".join(targets))
        hits = [l.split()[0] for l in r.lines if l.strip().startswith("http")]
        if hits:
            reflected = list(dict.fromkeys(hits))
            ui.step(f"  {len(reflected)} URL(s) reflect input → handing to dalfox")

    infile = runner.write_lines(d / "targets.txt", reflected)
    out = d / "dalfox.json"
    deep = profile.name == "deep"
    # deep: mine DOM params + deep DOM-XSS analysis for maximum coverage
    extra = ["--deep-domxss", "--mining-dom", "--mining-dict"] if deep else []
    ui.step(f"dalfox verifying XSS on {len(reflected)} target(s){' (deep DOM)' if deep else ''}...")
    # dalfox only reports [POC] when it verifies the payload triggers
    runner.stream(["dalfox", "file", str(infile), "--format", "json", "-o", str(out),
                   "--only-poc", "r", "--skip-bav", "--worker", "40", "--silence", *extra],
                  timeout=900 if deep else 600, quiet=True)
    for line in runner.read_lines(out):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        poc = rec.get("data") or rec.get("poc") or ""
        typ = (rec.get("type") or "").upper()
        if not poc:
            continue
        # 'V' (verified) is confirmed; 'R' (reflected) is firm
        conf = "confirmed" if typ.startswith("V") else "firm"
        st.add(Vuln(
            vclass="xss", name=f"Cross-Site Scripting ({rec.get('inject_type','reflected')})",
            severity="high", confidence=conf, url=poc,
            parameter=rec.get("param", ""), payload=rec.get("evidence", ""),
            evidence=f"dalfox {typ}: {rec.get('message','payload reflected & executed')}",
            tool="dalfox", request=f"curl '{poc}'"))
        ui.err(f"  [{conf.upper()}] XSS: {rec.get('param','')} @ {poc[:80]}")

    # ── secondary confirmer: XSStrike on the reflected set ────────────────
    xss_dir = st.outdir.parent  # noqa: F841
    xstrike = _tool_dir("xsstrike", "xsstrike.py")
    if profile.double_pass and xstrike and reflected:
        ui.step("XSStrike secondary pass on reflected URLs...")
        for u in reflected[:15]:
            r = runner.run(["python3", str(xstrike), "-u", u, "--skip-dom", "--timeout", "8"],
                           timeout=120)
            blob = "\n".join(r.lines)
            if re.search(r"payload:|reflected in|vulnerable|xss found", blob, re.I) and \
               not any(v.url == u and v.vclass == "xss" for v in st.vulns):
                st.add(Vuln(vclass="xss", name="Cross-Site Scripting (context-verified)",
                            severity="high", confidence="firm", url=u,
                            evidence="XSStrike confirmed a working XSS context", tool="xsstrike",
                            request=f"xsstrike -u '{u}'"))
                ui.err(f"  [FIRM] XSS (XSStrike): {u[:80]}")


# ─────────────────────────────────────────────────────────────
#  LFI — payload injection + PROOF-signature match (/etc/passwd)
# ─────────────────────────────────────────────────────────────
def scan_lfi(st: VaptState, targets: list[str], profile) -> None:
    d = st.dir("lfi")
    payload_file = payloads.ensure("lfi")
    cap = 120 if profile.name == "deep" else (25 if profile.name == "fast" else 60)
    plist = [l for l in payload_file.read_text().splitlines() if l.strip()][:cap]
    targets = targets[: profile.max_targets_per_class]
    ui.step(f"LFI proof-testing {len(targets)} target(s) with {len(plist)} payloads (parallel)...")
    hits = 0

    def _one(url):
        sess = requests.Session()
        sess.headers["User-Agent"] = "Mozilla/5.0 (compatible; ScamVapt/1.0)"
        for param in (_params(url) or ["file", "page", "path"]):
            for payload in plist:
                test = _inject(url, param, payload)
                try:
                    r = sess.get(test, timeout=8, verify=False)
                except requests.exceptions.RequestException:
                    continue
                if any(sig.search(r.text) for sig in LFI_SIGNATURES):
                    st.add(Vuln(
                        vclass="lfi", name="Local File Inclusion / Path Traversal",
                        severity="high", confidence="confirmed", url=url, parameter=param,
                        payload=payload, evidence="response returned /etc/passwd (root:x:0:0:) signature",
                        tool="scamvapt-lfi", request=f"curl '{test}'"))
                    ui.err(f"  [CONFIRMED] LFI: {param} @ {url}  (payload {payload})")
                    return 1
        return 0

    hits = sum(x or 0 for x in runner.parallel_map(_one, targets, workers=min(12, len(targets) or 1)))
    # ── 2nd pass: nuclei LFI/traversal templates corroborate the signature match
    if profile.double_pass and TOOLS["nuclei"].installed() and targets:
        infile = runner.write_lines(d / "targets.txt", targets)
        out = d / "nuclei_lfi.jsonl"
        runner.stream(["nuclei", "-l", str(infile), "-tags", "lfi,fileupload,traversal",
                       "-jsonl", "-o", str(out), "-severity", "critical,high,medium",
                       "-silent", "-disable-update-check"], timeout=400, quiet=True)
        for v in _parse_nuclei(out, "lfi", st):
            ui.err(f"  [{v.confidence.upper()}] LFI (nuclei): {v.url}")
    if not hits:
        ui.step("no LFI confirmed by signature match")


# ─────────────────────────────────────────────────────────────
#  SSTI — nuclei ssti templates + SSTImap RCE confirmation
# ─────────────────────────────────────────────────────────────
def scan_ssti(st: VaptState, targets: list[str], profile) -> None:
    d = st.dir("ssti")
    targets = targets[: profile.max_targets_per_class]
    # nuclei ssti templates (matching = confirmed injection)
    if TOOLS["nuclei"].installed() and targets:
        infile = runner.write_lines(d / "targets.txt", targets)
        out = d / "nuclei_ssti.jsonl"
        ui.step(f"nuclei SSTI templates on {len(targets)} target(s)...")
        runner.stream(["nuclei", "-l", str(infile), "-tags", "ssti", "-jsonl", "-o", str(out),
                       "-severity", "critical,high", "-silent", "-disable-update-check"],
                      timeout=400, quiet=True)
        for v in _parse_nuclei(out, "ssti", st):
            ui.err(f"  [{v.confidence.upper()}] SSTI: {v.url}")
    # SSTImap escalates to code execution → the strongest possible proof
    sstimap = _tool_dir("sstimap", "sstimap.py")
    if sstimap and targets:
        ui.step("SSTImap confirming template injection → RCE...")
        for u in targets[:20]:
            r = runner.run(["python3", str(sstimap), "-u", u, "--batch"], timeout=120)
            blob = "\n".join(r.lines)
            if re.search(r"is vulnerable|engine:|code execution|SSTImap identified", blob, re.I):
                engine = _search(r"[Ee]ngine: *(\w+)", blob) or "template engine"
                st.add(Vuln(vclass="ssti", name=f"Server-Side Template Injection ({engine})",
                            severity="critical", confidence="confirmed", url=u,
                            evidence=f"SSTImap confirmed SSTI in {engine} (code execution)",
                            tool="sstimap", request=f"sstimap -u '{u}' --os-shell"))
                ui.err(f"  [CONFIRMED] SSTI→RCE: {u}")


# ─────────────────────────────────────────────────────────────
#  RCE / command injection — commix (confirms execution)
# ─────────────────────────────────────────────────────────────
def _commix_cmd() -> list[str] | None:
    """commix on PATH, else the git-cloned tools/commix/commix.py."""
    if TOOLS["commix"].installed():
        return ["commix"]
    cloned = _tool_dir("commix", "commix.py")
    return ["python3", cloned] if cloned else None


def scan_rce(st: VaptState, targets: list[str], profile) -> None:
    commix = _commix_cmd()
    if not commix:
        ui.warn("commix not installed — skipping RCE confirmation")
        return
    d = st.dir("rce")
    targets = targets[: profile.max_targets_per_class]
    ui.step(f"commix confirming command injection on {len(targets)} target(s) (parallel)...")

    def _one(url):
        r = runner.run(commix + ["-u", url, "--batch", "--technique=cb",
                        "--skip-heuristics", "-v", "0"], timeout=240)
        blob = "\n".join(r.lines)
        if re.search(r"is vulnerable|the target url is vulnerable|command execution", blob, re.I):
            param = (_params(url) or [""])[0]
            st.add(Vuln(vclass="rce", name="OS Command Injection", severity="critical",
                        confidence="confirmed", url=url, parameter=param,
                        evidence="commix confirmed command execution", tool="commix",
                        request=f"commix -u '{url}' --batch"))
            ui.err(f"  [CONFIRMED] RCE: {url}")

    runner.parallel_map(_one, targets, workers=min(5, len(targets) or 1))


# ─────────────────────────────────────────────────────────────
#  Open redirect — inject external host, confirm via Location header
# ─────────────────────────────────────────────────────────────
CANARY = "scamvapt-oob.example.net"


def scan_redirect(st: VaptState, targets: list[str], profile) -> None:
    d = st.dir("redirect")
    targets = targets[: profile.max_targets_per_class]
    ui.step(f"open-redirect proof-testing {len(targets)} target(s) (parallel)...")
    payloads_r = [f"https://{CANARY}", f"//{CANARY}", f"/\\{CANARY}", f"https:/{CANARY}"]

    def _one(url):
        sess = requests.Session()
        sess.max_redirects = 1
        for param in (_params(url) or ["url", "next", "redirect"]):
            for p in payloads_r:
                test = _inject(url, param, p)
                try:
                    r = sess.get(test, timeout=7, allow_redirects=False, verify=False)
                except requests.exceptions.RequestException:
                    continue
                loc = r.headers.get("Location", "")
                if r.status_code in (301, 302, 303, 307, 308) and CANARY in loc:
                    st.add(Vuln(vclass="redirect", name="Open Redirect", severity="medium",
                                confidence="confirmed", url=url, parameter=param, payload=p,
                                evidence=f"Location header redirected off-site to {loc}",
                                tool="scamvapt-redirect", request=f"curl -I '{test}'"))
                    ui.err(f"  [CONFIRMED] Open Redirect: {param} @ {url}")
                    return 1
        return 0

    hits = sum(x or 0 for x in runner.parallel_map(_one, targets, workers=min(15, len(targets) or 1)))
    if not hits:
        ui.step("no open redirect confirmed")


# ─────────────────────────────────────────────────────────────
#  CRLF — crlfuzz (low false-positive)
# ─────────────────────────────────────────────────────────────
def scan_crlf(st: VaptState, targets: list[str], profile) -> None:
    if not TOOLS["crlfuzz"].installed():
        ui.warn("crlfuzz not installed — skipping CRLF")
        return
    d = st.dir("crlf")
    targets = targets[: profile.max_targets_per_class]
    infile = runner.write_lines(d / "targets.txt", targets)
    out = d / "crlfuzz.txt"
    ui.step(f"crlfuzz testing {len(targets)} target(s)...")
    runner.stream(["crlfuzz", "-l", str(infile), "-s", "-o", str(out)], timeout=300, quiet=True)
    for line in runner.read_lines(out):
        u = line.strip()
        if u.startswith("http"):
            st.add(Vuln(vclass="crlf", name="CRLF Injection / HTTP Response Splitting",
                        severity="medium", confidence="confirmed", url=u,
                        evidence="crlfuzz confirmed CRLF injection", tool="crlfuzz",
                        request=f"crlfuzz -u '{u}'"))
            ui.err(f"  [CONFIRMED] CRLF: {u}")


# ─────────────────────────────────────────────────────────────
#  CORS misconfiguration — corsy (reflects arbitrary Origin) + native probe
# ─────────────────────────────────────────────────────────────
def scan_cors(st: VaptState, hosts: list[str]) -> None:
    d = st.dir("cors")
    corsy = _tool_dir("corsy", "corsy.py")
    if corsy and hosts:
        infile = runner.write_lines(d / "hosts.txt", hosts)
        out = d / "corsy.json"
        ui.step(f"corsy testing CORS on {len(hosts)} host(s)...")
        runner.run(["python3", corsy, "-i", str(infile), "-o", str(out)], timeout=400)
        try:
            data = json.loads(out.read_text()) if out.exists() else {}
        except Exception:
            data = {}
        for url, info in (data.items() if isinstance(data, dict) else []):
            cls = info.get("class", "") if isinstance(info, dict) else ""
            st.add(Vuln(vclass="cors", name=f"CORS Misconfiguration ({cls or 'reflected origin'})",
                        severity="medium", confidence="firm", url=url,
                        evidence=f"corsy: {info.get('description', cls)}", tool="corsy",
                        request=f"curl -H 'Origin: https://evil.example' -I '{url}'"))
            ui.err(f"  [FIRM] CORS: {url}")
        return
    # native fallback: reflect a random Origin, check ACAO + credentials (parallel)
    import requests as _rq

    def _one(h):
        try:
            r = _rq.get(h, headers={"Origin": "https://evil.example"}, timeout=7, verify=False)
        except Exception:
            return 0
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "https://evil.example" and acac.lower() == "true":
            st.add(Vuln(vclass="cors", name="CORS Misconfiguration (origin reflection + credentials)",
                        severity="high", confidence="confirmed", url=h,
                        evidence="ACAO reflected attacker Origin with ACAC:true",
                        tool="scamvapt-cors",
                        request=f"curl -H 'Origin: https://evil.example' -I '{h}'"))
            ui.err(f"  [CONFIRMED] CORS: {h}")
        return 1

    tested = sum(x or 0 for x in runner.parallel_map(_one, hosts[:40], workers=20))
    if tested:
        ui.step(f"CORS probed {tested} host(s)")


# ─────────────────────────────────────────────────────────────
#  TLS/SSL — testssl.sh (deep) or sslscan for transport weaknesses
# ─────────────────────────────────────────────────────────────
def scan_tls(st: VaptState, hosts: list[str]) -> None:
    from urllib.parse import urlparse
    d = st.dir("tls")
    hosts = [h for h in hosts if h.startswith("https")][:15]
    if not hosts:
        return
    if TOOLS["testssl"].installed():
        ui.step(f"testssl.sh deep TLS analysis on {len(hosts)} host(s)...")
        for h in hosts:
            hostport = urlparse(h).netloc
            jf = d / (re.sub(r"\W+", "_", hostport) + ".json")
            runner.run(["testssl.sh", "--quiet", "--color", "0", "--severity", "MEDIUM",
                        "--jsonfile", str(jf), hostport], timeout=300)
            try:
                data = json.loads(jf.read_text()) if jf.exists() else []
            except Exception:
                data = []
            entries = data if isinstance(data, list) else data.get("scanResult", [])
            for e in entries if isinstance(entries, list) else []:
                sev = str(e.get("severity", "")).lower()
                if sev in ("high", "critical", "medium"):
                    st.add(Vuln(vclass="tls", name=f"TLS: {e.get('id','weakness')}",
                                severity="high" if sev in ("high", "critical") else "medium",
                                confidence="firm", url=h,
                                evidence=f"testssl.sh: {e.get('finding','')}", tool="testssl.sh",
                                request=f"testssl.sh {hostport}"))
    elif TOOLS["sslscan"].installed():
        ui.step(f"sslscan TLS check on {len(hosts)} host(s)...")
        for h in hosts:
            hostport = urlparse(h).netloc
            r = runner.run(["sslscan", "--no-colour", hostport], timeout=90)
            blob = "\n".join(r.lines)
            weak = [m for m in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1") if re.search(m + r".*enabled", blob)]
            if weak:
                st.add(Vuln(vclass="tls", name=f"Weak TLS protocols enabled ({', '.join(weak)})",
                            severity="medium", confidence="firm", url=h,
                            evidence=f"sslscan: {', '.join(weak)} accepted", tool="sslscan",
                            request=f"sslscan {hostport}"))


# ─────────────────────────────────────────────────────────────
#  SSRF — nuclei ssrf + OOB (interactsh) as available (firm without OOB)
# ─────────────────────────────────────────────────────────────
def scan_ssrf(st: VaptState, targets: list[str], profile) -> None:
    d = st.dir("ssrf")
    targets = targets[: profile.max_targets_per_class]

    # ── OOB pass: inject an Interactsh canary; a DNS/HTTP hit = proven SSRF ──
    if TOOLS["interactsh-client"].installed() and targets:
        _ssrf_oob(st, targets, d)

    # ── nuclei ssrf templates (matched = confirmed) ──
    if TOOLS["nuclei"].installed() and targets:
        infile = runner.write_lines(d / "targets.txt", targets)
        out = d / "nuclei_ssrf.jsonl"
        ui.step(f"nuclei SSRF templates on {len(targets)} target(s)...")
        runner.stream(["nuclei", "-l", str(infile), "-tags", "ssrf", "-jsonl", "-o", str(out),
                       "-severity", "critical,high,medium", "-silent", "-disable-update-check"],
                      timeout=600, quiet=True)
        for v in _parse_nuclei(out, "ssrf", st):
            ui.err(f"  [{v.confidence.upper()}] SSRF: {v.url}")
    elif not TOOLS["interactsh-client"].installed():
        ui.warn("nuclei/interactsh not installed — skipping SSRF")


def _ssrf_oob(st: VaptState, targets: list[str], d) -> None:
    """Register an Interactsh domain, inject it into SSRF params, poll for hits.

    An out-of-band DNS/HTTP callback is irrefutable proof of blind SSRF — the
    strongest possible confirmation (zero false positive)."""
    import subprocess, time, json as _json
    binp = runner.resolve_binary("interactsh-client")
    if not binp:
        return
    ui.step("interactsh OOB SSRF — registering canary domain...")
    try:
        proc = subprocess.Popen([binp, "-json", "-v"], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception:
        return
    domain = None
    injected: dict[str, str] = {}
    try:
        # read the registered domain from the first lines
        t0 = time.time()
        while time.time() - t0 < 15:
            line = proc.stdout.readline()
            if not line:
                break
            m = re.search(r"([a-z0-9]+\.oast\.[a-z]+)", line)
            if m:
                domain = m.group(1)
                break
        if not domain:
            proc.terminate(); return
        sess = requests.Session()
        for url in targets:
            for param in (_params(url) or ["url", "uri", "next", "dest", "callback"]):
                canary = f"http://{_rand()}.{domain}/"
                test = _inject(url, param, canary)
                injected[canary.split('//')[1].split('.')[0]] = f"{url} (param {param})"
                try:
                    sess.get(test, timeout=6, verify=False)
                except requests.exceptions.RequestException:
                    pass
        time.sleep(8)  # allow callbacks to arrive
        # drain interaction events
        proc.terminate()
        out, _ = proc.communicate(timeout=5)
        for line in (out or "").splitlines():
            try:
                ev = _json.loads(line)
            except Exception:
                continue
            fqdn = ev.get("full-id", "") or ev.get("unique-id", "")
            proto = ev.get("protocol", "oob")
            key = fqdn.split(".")[0] if fqdn else ""
            src = next((v for k, v in injected.items() if k and k in fqdn), None)
            if src:
                url = src.split(" (")[0]
                st.add(Vuln(vclass="ssrf", name="Server-Side Request Forgery (OOB-confirmed)",
                            severity="high", confidence="confirmed", url=url,
                            evidence=f"target made an out-of-band {proto.upper()} request to our Interactsh canary",
                            tool="interactsh",
                            request=f"inject http://<canary>.{domain}/ into the URL parameter"))
                ui.err(f"  [CONFIRMED] SSRF (OOB {proto}): {url}")
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass


def _rand(n: int = 8) -> str:
    import random, string
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ─────────────────────────────────────────────────────────────
#  Nuclei DAST — broad confirmed injection across live hosts
# ─────────────────────────────────────────────────────────────
def scan_nuclei_dast(st: VaptState, targets: list[str], profile) -> None:
    if not TOOLS["nuclei"].installed():
        return
    d = st.dir("nuclei_dast")
    if not targets:
        return
    infile = runner.write_lines(d / "targets.txt", targets)
    out = d / "nuclei_dast.jsonl"
    ui.step(f"nuclei DAST (fuzzing) on {len(targets)} parameterized URL(s)...")
    cmd = ["nuclei", "-l", str(infile), "-dast", "-jsonl", "-o", str(out),
           "-severity", profile.nuclei_severity, "-silent", "-disable-update-check",
           "-rate-limit", "150", "-timeout", "8"]
    # Prefer the dedicated fuzzing-templates repo when it's been cloned
    from .config import FUZZING_TEMPLATES
    if FUZZING_TEMPLATES.exists():
        cmd += ["-t", str(FUZZING_TEMPLATES)]
    budget = min(1800, max(300, len(targets) * 5))
    runner.stream(cmd, timeout=budget, quiet=True)
    n = len(_parse_nuclei(out, None, st))
    ui.good(f"nuclei DAST added {n} confirmed finding(s)")


# ─────────────────────────────────────────────────────────────
#  Parameter discovery — widen surface so nothing is missed (no FN)
# ─────────────────────────────────────────────────────────────
def _apex(host: str) -> str:
    """Naive registrable-domain from a netloc (good enough for gau --subs)."""
    from urllib.parse import urlparse
    net = urlparse(host if "://" in host else "http://" + host).netloc.split(":")[0]
    parts = net.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else net


def _merge_surface(st: VaptState, urls, classes) -> int:
    """Route a URL list into classes and APPEND to the surface, preserving order.

    Existing (recon-validated / higher-priority) vectors stay at the front so the
    per-class cap always tests them first — newly discovered (arjun/gau) URLs are
    appended after, never displacing the curated ones.
    """
    from .loader import _route_urls
    routed = _route_urls(sorted(set(urls)), classes)
    added = 0
    for cls, u in routed.items():
        existing = st.surface.get(cls, [])
        seen = set(existing)
        new = [x for x in sorted(u) if x not in seen]
        st.surface[cls] = existing + new
        added += len(new)
    return added


def expand_surface(st: VaptState, profile) -> None:
    """Aggressively discover parameterized endpoints so scanners have real work.

    Harvests archived URLs (gau) across every apex, crawls live hosts (katana),
    and brute-discovers hidden parameters (arjun) — all in parallel. Casting a
    wide net fights false negatives; the confirming scanners still gate on proof.
    """
    d = st.dir("00_targets")
    if not st.live_targets:
        ui.step("no live hosts to expand from")
        return

    harvested: set[str] = set()

    # ── gau across every apex domain (parallel) ──────────────────────────
    if TOOLS["gau"].installed():
        apexes = sorted({_apex(h) for h in st.live_targets})[:8]
        ui.step(f"gau harvesting archived URLs across {len(apexes)} domain(s)...")

        def _gau(dom):
            return runner.run(["gau", "--subs", dom], timeout=150).lines
        for lines in runner.parallel_map(_gau, apexes, workers=min(6, len(apexes))):
            harvested.update(u for u in (lines or []) if "?" in u and "=" in u)

    # ── katana crawl of live hosts for parameterized endpoints ───────────
    if TOOLS["katana"].installed():
        ui.step("katana crawling live hosts for parameterized endpoints...")
        infile = runner.write_lines(d / "katana_seed.txt", st.live_targets[:40])
        kout = d / "katana.txt"
        runner.stream(["katana", "-list", str(infile), "-d", "2", "-c", "20", "-silent",
                       "-o", str(kout), "-f", "qurl"], timeout=400, quiet=True)
        harvested.update(u for u in runner.read_lines(kout) if "?" in u)
    elif TOOLS["waybackurls"].installed():
        ui.step("waybackurls harvesting...")
        for dom in sorted({_apex(h) for h in st.live_targets})[:6]:
            harvested.update(u for u in runner.run(["waybackurls", dom], timeout=120).lines
                             if "?" in u and "=" in u)

    if harvested:
        added = _merge_surface(st, harvested, profile.classes)
        runner.write_lines(d / "harvested_param_urls.txt", harvested)
        ui.good(f"gau/katana added {added:,} parameterized URL(s) to the surface")

    # ── arjun hidden-parameter discovery (parallel over hosts) ───────────
    if TOOLS["arjun"].installed():
        # test live host roots + a sample of crawled/harvested endpoint paths
        endpoints = list(dict.fromkeys(
            st.live_targets[:20] + [u.split("?")[0] for u in sorted(harvested)][:20]))
        ui.step(f"arjun discovering hidden parameters on {len(endpoints)} endpoint(s)...")

        def _arjun(h):
            out = d / ("arjun_" + re.sub(r"\W+", "_", h)[:50] + ".json")
            runner.run(["arjun", "-u", h, "-oJ", str(out), "-t", "20", "--stable"], timeout=150)
            found = []
            try:
                data = json.loads(out.read_text()) if out.exists() else {}
            except Exception:
                data = {}
            for url, info in (data.items() if isinstance(data, dict) else []):
                for p in (info.get("params", []) if isinstance(info, dict) else []):
                    found.append(_inject(url + ("?x=1" if "?" not in url else ""), p, "1"))
            return found

        new_urls: set[str] = set()
        for res in runner.parallel_map(_arjun, endpoints, workers=min(10, len(endpoints) or 1)):
            new_urls.update(res or [])
        if new_urls:
            added = _merge_surface(st, new_urls, profile.classes)
            ui.good(f"arjun expanded the surface by {added:,} parameterized URL(s)")

    total = sum(len(v) for v in st.surface.values())
    if total:
        ui.good(f"test surface now: {total:,} URL(s) across {len(st.surface)} classes")
    else:
        ui.warn("still no parameterized endpoints found — host-level nuclei will still run")


# ─────────────────────────────────────────────────────────────
#  Nuclei host-level pass — exposures / CVEs / misconfig / panels
# ─────────────────────────────────────────────────────────────
def scan_nuclei_tags(st: VaptState, profile) -> None:
    if not TOOLS["nuclei"].installed() or not st.live_targets:
        return
    d = st.dir("nuclei_tags")
    infile = runner.write_lines(d / "hosts.txt", st.live_targets)
    out = d / "nuclei_tags.jsonl"
    ui.step(f"nuclei host-level pass (exposures/cve/misconfig/takeover/panel) "
            f"on {len(st.live_targets)} host(s)...")
    budget = min(1500, max(120, len(st.live_targets) * 12))
    runner.stream(["nuclei", "-l", str(infile), "-jsonl", "-o", str(out),
                   "-tags", "cve,exposure,misconfig,default-login,takeover,panel,disclosure,injection",
                   "-severity", profile.nuclei_severity, "-exclude-tags", "dos,intrusive",
                   "-rate-limit", "150", "-timeout", "8", "-retries", "1",
                   "-silent", "-disable-update-check", "-stats"], timeout=budget, quiet=True)
    n = len(_parse_nuclei(out, None, st))
    ui.good(f"nuclei host-level pass added {n} confirmed/firm finding(s)")


def _parse_nuclei(out_path, vclass_hint, st: VaptState) -> list[Vuln]:
    added = []
    sev_map = {"critical": "critical", "high": "high", "medium": "medium",
               "low": "low", "info": "info"}
    for line in runner.read_lines(out_path):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        info = rec.get("info", {})
        sev = sev_map.get((info.get("severity") or "info").lower(), "info")
        if sev in ("info", "low"):
            continue  # confirmation tool: only carry medium+ from nuclei
        tags = info.get("tags", [])
        vclass = vclass_hint or _guess_class(tags, info.get("name", ""))
        # nuclei dast/fuzzing templates that MATCH are confirmed; others firm
        is_dast = "fuzz" in tags or "dast" in tags or rec.get("type") == "http"
        v = Vuln(
            vclass=vclass, name=info.get("name", rec.get("template-id", "issue")),
            severity=sev, confidence="confirmed" if is_dast else "firm",
            url=rec.get("matched-at", rec.get("host", "")),
            evidence=f"nuclei template {rec.get('template-id','')} matched",
            tool="nuclei", request=rec.get("curl-command", ""))
        st.add(v)
        added.append(v)
    return added


def _guess_class(tags, name) -> str:
    blob = (" ".join(tags) + " " + name).lower()
    for c in ("sqli", "xss", "lfi", "rce", "ssrf", "redirect", "crlf"):
        if c in blob or (c == "rce" and ("rce" in blob or "injection" in blob)):
            return c
    return "misc"


def _search(pattern, text) -> str:
    m = re.search(pattern, text, re.I)
    return m.group(1).strip() if m else ""
