"""Shared recon state — the single object every phase reads from and writes to.

Keeping all discovered assets in one place makes dedup, cross-referencing
(which subdomain served which URL), and the final report straightforward.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class LiveHost:
    url: str
    host: str = ""
    status: int = 0
    title: str = ""
    webserver: str = ""
    tech: list[str] = field(default_factory=list)
    ip: str = ""
    cdn: str = ""
    content_length: int = 0
    scheme: str = ""
    validated: bool = False       # confirmed reachable by an independent curl/HTTP pass
    final_url: str = ""           # URL after following redirects
    response_ms: int = 0          # round-trip latency of the validation request


@dataclass
class Finding:
    template: str
    name: str
    severity: str
    host: str
    matched: str = ""
    tags: str = ""


@dataclass
class ReconState:
    target: str
    outdir: Path
    profile_name: str = "standard"
    started: datetime = field(default_factory=datetime.now)
    finished: datetime | None = None

    # asset stores
    subdomains: set[str] = field(default_factory=set)
    discovered: int = 0                                          # total discovered before DNS filter
    unresolved: set[str] = field(default_factory=set)           # dropped: no DNS record
    resolved: dict[str, dict] = field(default_factory=dict)      # host -> {a, aaaa, cname}
    live: dict[str, LiveHost] = field(default_factory=dict)      # url -> LiveHost
    ports: dict[str, list[int]] = field(default_factory=dict)    # host -> [ports]
    ports_unreliable: bool = False                               # network interception detected
    nmap_services: dict[str, list[dict]] = field(default_factory=dict)
    urls: set[str] = field(default_factory=set)
    js_files: set[str] = field(default_factory=set)
    endpoints: set[str] = field(default_factory=set)
    interesting: dict[str, list] = field(default_factory=dict)  # attack-class -> [urls]
    validated_vectors: dict[str, list] = field(default_factory=dict)  # attack-class -> [reachable urls]
    technologies: dict[str, int] = field(default_factory=dict)   # tech -> count
    findings: list[Finding] = field(default_factory=list)
    takeovers: list[dict] = field(default_factory=list)
    asn_info: list[str] = field(default_factory=list)
    whois: str = ""
    screenshots_dir: Path | None = None

    # provenance: which tool contributed which subdomains
    sources: dict[str, int] = field(default_factory=dict)

    def dir(self, name: str) -> Path:
        d = self.outdir / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def live_urls(self) -> list[str]:
        return sorted(self.live.keys())

    @property
    def resolved_hosts(self) -> list[str]:
        return sorted(self.resolved.keys())

    @property
    def duration(self) -> str:
        end = self.finished or datetime.now()
        secs = int((end - self.started).total_seconds())
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m}m {s}s" if h else f"{m}m {s}s"

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity if f.severity in counts else "info"] += 1
        return counts
