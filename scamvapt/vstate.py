"""VAPT state — the confidence-graded finding model and run container.

The whole tool hinges on `confidence`:
  * confirmed  — a tool proved exploitability (reported as a real vuln)
  * firm       — strong signal from a reliable detector, one step from proof
  * tentative  — weak/heuristic hit → quarantined for manual review, never a "vuln"

Only `confirmed` (and, in reports, `firm`) count toward the vulnerability totals.
This is how false positives are kept at zero in the headline numbers.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
CONFIDENCE_ORDER = ["confirmed", "firm", "tentative"]


@dataclass
class Vuln:
    vclass: str                 # sqli | xss | lfi | rce | ssti | ssrf | redirect | crlf
    name: str
    severity: str               # critical | high | medium | low | info
    confidence: str             # confirmed | firm | tentative
    url: str                    # the exact endpoint tested
    parameter: str = ""         # the injected parameter, if known
    payload: str = ""           # the payload that worked
    evidence: str = ""          # tool proof (dbms, reflected context, /etc/passwd line…)
    tool: str = ""              # which tool produced it
    request: str = ""           # reproducible request / PoC command
    remediation: str = ""
    steps: list = field(default_factory=list)      # numbered steps to reproduce
    references: list = field(default_factory=list) # OWASP / CWE / CVE links
    cwe: str = ""

    @property
    def is_reportable(self) -> bool:
        return self.confidence in ("confirmed", "firm")


CWE = {"sqli": "CWE-89", "xss": "CWE-79", "lfi": "CWE-98/CWE-22", "rce": "CWE-77/CWE-78",
       "ssti": "CWE-1336", "ssrf": "CWE-918", "redirect": "CWE-601", "crlf": "CWE-113",
       "cors": "CWE-942", "tls": "CWE-327", "secret": "CWE-798", "misc": "CWE-693"}

REFERENCES = {
    "sqli": ["https://owasp.org/www-community/attacks/SQL_Injection",
             "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    "xss": ["https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    "lfi": ["https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Prevention_Cheat_Sheet.html"],
    "rce": ["https://owasp.org/www-community/attacks/Command_Injection"],
    "ssti": ["https://portswigger.net/web-security/server-side-template-injection"],
    "ssrf": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
             "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
    "redirect": ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
    "crlf": ["https://owasp.org/www-community/vulnerabilities/CRLF_Injection"],
    "cors": ["https://portswigger.net/web-security/cors"],
    "tls": ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
    "secret": ["https://cwe.mitre.org/data/definitions/798.html"],
}


def default_steps(v: "Vuln") -> list:
    """Class-specific, evidence-anchored steps to reproduce the finding."""
    u, p, pay = v.url, v.parameter or "the vulnerable parameter", v.payload
    inj = f"Set `{p}` to: {pay}" if pay else f"Inject a class payload into `{p}`"
    base = {
        "sqli": [
            f"Send a request to `{u}`.",
            f"Locate the injectable parameter `{p}`.",
            f"{inj or 'Inject a boolean/time payload, e.g. '+chr(39)+' AND SLEEP(5)-- -'}.",
            "Observe DBMS-dependent behaviour (time delay, error, or boolean difference).",
            f"Confirm & enumerate: `{v.request or 'sqlmap -u '+chr(39)+u+chr(39)+' --batch --dbs'}`.",
        ],
        "xss": [
            f"Browse to `{u}`.",
            f"{inj or 'Set '+p+' to a script payload, e.g. \"><svg onload=alert(1)>'}.",
            "Load the URL in a browser — the injected JavaScript executes in page context.",
            f"Confirm: `{v.request or 'dalfox url '+chr(39)+u+chr(39)}`.",
        ],
        "lfi": [
            f"Take the request to `{u}`.",
            f"Replace `{p}` with a traversal payload: {pay or '../../../../etc/passwd'}.",
            "Observe the HTTP response returning file contents (e.g. `root:x:0:0:` from /etc/passwd).",
            f"Reproduce: `{v.request or 'curl '+chr(39)+u+chr(39)}`.",
        ],
        "rce": [
            f"Send a request to `{u}`.",
            f"{inj or 'Append a command separator + command to '+p+', e.g. ;id'}.",
            "Observe command output reflected in the response (e.g. `uid=` from `id`).",
            f"Confirm: `{v.request or 'commix -u '+chr(39)+u+chr(39)+' --batch'}`.",
        ],
        "ssti": [
            f"Send a request to `{u}`.",
            f"Inject a template expression into `{p}` (e.g. `${{7*7}}` / `{{{{7*7}}}}`).",
            "Observe the arithmetic is evaluated server-side (returns 49) — template engine confirmed.",
            f"Escalate: `{v.request or 'sstimap -u '+chr(39)+u+chr(39)}`.",
        ],
        "ssrf": [
            f"Send a request to `{u}`.",
            f"Point `{p}` at an internal/OOB target (e.g. an Interactsh URL or 169.254.169.254).",
            "Observe the server making the outbound request (OOB interaction or internal response).",
            f"Confirm: `{v.request or 'nuclei -u '+chr(39)+u+chr(39)+' -tags ssrf'}`.",
        ],
        "redirect": [
            f"Send a request to `{u}`.",
            f"Set `{p}` to an external URL: {pay or 'https://evil.example'}.",
            "Follow the response — the `Location` header redirects off-site to the attacker URL.",
            f"Reproduce: `{v.request or 'curl -I '+chr(39)+u+chr(39)}`.",
        ],
        "crlf": [
            f"Send a request to `{u}`.",
            f"Inject encoded CRLF (`%0d%0a`) into `{p}` followed by a header/body.",
            "Observe the injected header/content in the HTTP response (response splitting).",
            f"Confirm: `{v.request or 'crlfuzz -u '+chr(39)+u+chr(39)}`.",
        ],
        "cors": [
            f"Send a request to `{u}` with header `Origin: https://evil.example`.",
            "Observe `Access-Control-Allow-Origin` reflects the attacker origin with credentials allowed.",
            f"Reproduce: `curl -H 'Origin: https://evil.example' -I '{u}'`.",
        ],
    }
    return base.get(v.vclass, [
        f"Reproduce the request against `{u}`.",
        f"Evidence: {v.evidence}",
        f"PoC: `{v.request}`" if v.request else "See tool output for the exact request.",
    ])


REMEDIATION = {
    "sqli": "Use parameterized queries / prepared statements; never concatenate user input into SQL. Apply least-privilege DB accounts and a WAF as defense-in-depth.",
    "xss": "Context-aware output encoding, a strict Content-Security-Policy, and input validation. Prefer framework auto-escaping; sanitize HTML with a vetted library.",
    "lfi": "Never pass user input to file APIs. Use allow-lists of file IDs, canonicalize + verify paths stay in the intended dir, disable url_include/wrappers.",
    "rce": "Avoid shelling out with user input; use safe library calls. If unavoidable, strict allow-list validation and argument arrays (never a shell string).",
    "ssrf": "Allow-list outbound hosts, resolve+pin IPs and block private/link-local ranges, drop redirects, and require auth on internal metadata endpoints.",
    "redirect": "Use an allow-list of redirect targets or signed/relative-only redirects; never redirect to a raw user-supplied absolute URL.",
    "crlf": "Reject CR/LF in header-bound input and use framework header APIs that encode/validate values.",
    "cors": "Reflect Origin only from a strict allow-list; never combine a wildcard/echoed Origin with Access-Control-Allow-Credentials: true.",
    "tls": "Disable SSLv2/SSLv3/TLS1.0/1.1 and weak ciphers; enable TLS1.2+ with forward-secrecy suites, HSTS, and a valid certificate chain.",
    "secret": "Revoke and rotate the exposed credential immediately, remove it from client-served assets, and load secrets from a server-side vault.",
}


@dataclass
class VaptState:
    target_label: str
    outdir: Path
    profile_name: str = "standard"
    started: datetime = field(default_factory=datetime.now)
    finished: datetime | None = None

    # test surface, grouped by vuln class
    surface: dict[str, list[str]] = field(default_factory=dict)   # class -> [urls]
    live_targets: list[str] = field(default_factory=list)

    vulns: list[Vuln] = field(default_factory=list)               # all graded findings
    tools_used: dict[str, int] = field(default_factory=dict)
    source_recon: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def dir(self, name: str) -> Path:
        d = self.outdir / name
        with self._lock:
            d.mkdir(parents=True, exist_ok=True)
        return d

    def add(self, v: Vuln) -> None:
        if not v.remediation:
            v.remediation = REMEDIATION.get(v.vclass, "")
        if not v.cwe:
            v.cwe = CWE.get(v.vclass, "")
        if not v.references:
            v.references = list(REFERENCES.get(v.vclass, []))
        if not v.steps:
            v.steps = default_steps(v)
        with self._lock:  # thread-safe: scanners run concurrently
            self.vulns.append(v)
            self.tools_used[v.tool] = self.tools_used.get(v.tool, 0) + 1

    @property
    def confirmed(self) -> list[Vuln]:
        return [v for v in self.vulns if v.confidence == "confirmed"]

    @property
    def reportable(self) -> list[Vuln]:
        return [v for v in self.vulns if v.is_reportable]

    @property
    def review(self) -> list[Vuln]:
        return [v for v in self.vulns if v.confidence == "tentative"]

    def severity_counts(self, only_reportable: bool = True) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        pool = self.reportable if only_reportable else self.vulns
        for v in pool:
            counts[v.severity if v.severity in counts else "info"] += 1
        return counts

    @property
    def duration(self) -> str:
        end = self.finished or datetime.now()
        secs = int((end - self.started).total_seconds())
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m}m {s}s" if h else f"{m}m {s}s"
