"""Central configuration: platform detection, tool registry, wordlist registry.

Every tool is described once here — its binary name, what it's for, and how to
install it on each supported platform (Kali/Parrot via apt, macOS via brew, and
the go/pip/git fallbacks that work everywhere). The rest of the framework reads
from this registry so adding a tool is a one-line change.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# ─────────────────────────────────────────────────────────────
#  Paths
# ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "recon_output"
WORDLIST_DIR = BASE_DIR / "wordlists"
RESOLVERS_FILE = WORDLIST_DIR / "resolvers.txt"                 # big list — brute-force only
RESOLVERS_TRUSTED_FILE = WORDLIST_DIR / "resolvers-trusted.txt"  # small curated — resolution/validation
SUBS_WORDLIST = WORDLIST_DIR / "subdomains_merged.txt"
PERMUTATION_WORDLIST = WORDLIST_DIR / "permutations.txt"

for _d in (OUTPUT_DIR, WORDLIST_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────
#  Platform detection
# ─────────────────────────────────────────────────────────────
@dataclass
class Platform:
    system: str          # "macos" | "linux"
    distro: str          # "kali" | "parrot" | "debian" | "macos" | "unknown"
    arch: str            # "arm64" | "amd64"
    pkg_manager: str     # "brew" | "apt" | None

    @property
    def is_mac(self) -> bool:
        return self.system == "macos"

    @property
    def is_linux(self) -> bool:
        return self.system == "linux"


def detect_platform() -> Platform:
    sysname = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"

    if sysname == "darwin":
        return Platform("macos", "macos", arch, "brew" if shutil.which("brew") else None)

    # Linux — sniff the distro from os-release
    distro = "unknown"
    osr = Path("/etc/os-release")
    if osr.exists():
        text = osr.read_text().lower()
        if "kali" in text:
            distro = "kali"
        elif "parrot" in text:
            distro = "parrot"
        elif "debian" in text or "ubuntu" in text:
            distro = "debian"
    pkg = "apt" if shutil.which("apt-get") or shutil.which("apt") else None
    return Platform("linux", distro, arch, pkg)


PLATFORM = detect_platform()


def go_bin_dir() -> Path:
    """Where `go install` drops binaries."""
    gopath = os.environ.get("GOPATH")
    if not gopath:
        try:
            gopath = subprocess.check_output(["go", "env", "GOPATH"], text=True).strip()
        except Exception:
            gopath = str(Path.home() / "go")
    return Path(gopath) / "bin"


# ─────────────────────────────────────────────────────────────
#  Tool registry
# ─────────────────────────────────────────────────────────────
@dataclass
class Tool:
    name: str                       # binary name on PATH
    purpose: str
    # install recipes; first available strategy for the platform is used
    brew: str | None = None         # brew formula
    apt: str | None = None          # apt package
    go: str | None = None           # `go install <go>`
    pip: str | None = None          # `pip install <pip>`
    git: str | None = None          # git clone URL (script tools)
    binary: bool = False            # installed via release binary / special
    optional: bool = False          # nice-to-have, not core
    version_cmd: list[str] = field(default_factory=lambda: ["--version"])

    def installed(self) -> bool:
        if shutil.which(self.name):
            return True
        # go tools may live in ~/go/bin even if not on PATH yet
        if (go_bin_dir() / self.name).exists():
            return True
        # git-cloned script tools live under <repo>/tools/<name>/
        if self.git:
            tdir = BASE_DIR / "tools" / self.name
            if tdir.exists() and any(tdir.iterdir()):
                return True
        return False

    def path(self) -> str:
        p = shutil.which(self.name)
        if p:
            return p
        cand = go_bin_dir() / self.name
        return str(cand) if cand.exists() else self.name


# The full toolchain — grouped by recon phase. 25+ tools.
TOOLS: dict[str, Tool] = {
    # ── Passive subdomain enumeration ──────────────────────────
    "subfinder":   Tool("subfinder", "Passive subdomain discovery (30+ sources)",
                         brew="subfinder", go="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "amass":       Tool("amass", "OWASP passive+active subdomain / OSINT engine",
                         brew="amass", apt="amass", go="github.com/owasp-amass/amass/v4/...@master"),
    "assetfinder": Tool("assetfinder", "Fast passive subdomain finder",
                         go="github.com/tomnomnom/assetfinder@latest"),
    "findomain":   Tool("findomain", "Cross-platform subdomain finder (Rust)",
                         brew="findomain", binary=True, optional=True),
    "github-subdomains": Tool("github-subdomains", "Subdomains scraped from GitHub code search",
                         go="github.com/gwen001/github-subdomains@latest", optional=True),
    "uncover":     Tool("uncover", "Shodan/Censys/Fofa host discovery",
                         brew="uncover", go="github.com/projectdiscovery/uncover/cmd/uncover@latest", optional=True),
    "cero":        Tool("cero", "Subdomains from TLS certificate SANs",
                         go="github.com/glebarez/cero@latest", optional=True),
    "dnsgen":      Tool("dnsgen", "Permutation generator (wordlist-based)",
                         pip="dnsgen", optional=True),

    # ── Active DNS brute / resolution / permutation ────────────
    "dnsx":        Tool("dnsx", "Fast DNS resolver + brute-forcer",
                         brew="dnsx", go="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "puredns":     Tool("puredns", "Accurate mass DNS brute w/ wildcard filtering",
                         go="github.com/d3mondev/puredns/v2@latest"),
    "massdns":     Tool("massdns", "High-performance DNS stub resolver",
                         brew="massdns", apt="massdns"),
    "shuffledns":  Tool("shuffledns", "massdns wrapper for brute + resolve",
                         brew="shuffledns", go="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"),
    "gotator":     Tool("gotator", "DNS permutation / mutation generator",
                         go="github.com/Josue87/gotator@latest"),
    "alterx":      Tool("alterx", "Pattern-based subdomain permutation (PD)",
                         brew="alterx", go="github.com/projectdiscovery/alterx/cmd/alterx@latest", optional=True),

    # ── Live host probing / fingerprint ────────────────────────
    "httpx":       Tool("httpx", "HTTP prober: status, title, tech, TLS, CDN",
                         brew="httpx", go="github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "tlsx":        Tool("tlsx", "TLS grabber (SANs, cert data, JARM)",
                         brew="tlsx", go="github.com/projectdiscovery/tlsx/cmd/tlsx@latest", optional=True),
    "whatweb":     Tool("whatweb", "Web technology fingerprinter",
                         brew="whatweb", apt="whatweb", optional=True),

    # ── Ports / network ────────────────────────────────────────
    "naabu":       Tool("naabu", "Fast SYN/CONNECT port scanner",
                         brew="naabu", go="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "nmap":        Tool("nmap", "Service/version detection + NSE scripting",
                         brew="nmap", apt="nmap"),
    "asnmap":      Tool("asnmap", "ASN -> CIDR range mapping",
                         brew="asnmap", go="github.com/projectdiscovery/asnmap/cmd/asnmap@latest", optional=True),
    "mapcidr":     Tool("mapcidr", "CIDR expansion / aggregation",
                         brew="mapcidr", go="github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest", optional=True),

    # ── URL / endpoint discovery ───────────────────────────────
    "katana":      Tool("katana", "Fast crawler w/ JS parsing + headless",
                         brew="katana", go="github.com/projectdiscovery/katana/cmd/katana@latest"),
    "gau":         Tool("gau", "URLs from Wayback/CommonCrawl/OTX/URLScan",
                         go="github.com/lc/gau/v2/cmd/gau@latest"),
    "waybackurls": Tool("waybackurls", "URLs from the Wayback Machine",
                         go="github.com/tomnomnom/waybackurls@latest"),
    "gospider":    Tool("gospider", "Fast web spider",
                         go="github.com/jaeles-project/gospider@latest", optional=True),
    "hakrawler":   Tool("hakrawler", "Fast crawler for endpoint discovery",
                         go="github.com/hakluke/hakrawler@latest", optional=True),

    # ── JavaScript / secrets ───────────────────────────────────
    "subjs":       Tool("subjs", "Extract JS file URLs from a host list",
                         go="github.com/lc/subjs@latest", optional=True),

    # ── Vuln-adjacent recon (misconfig / takeover / exposures) ─
    "nuclei":      Tool("nuclei", "Template scanner: exposures, tech, takeovers, CVEs",
                         brew="nuclei", go="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "subzy":       Tool("subzy", "Subdomain takeover detector",
                         go="github.com/PentestPad/subzy@latest", optional=True),

    # ── Visual recon ───────────────────────────────────────────
    "gowitness":   Tool("gowitness", "Headless screenshots of live hosts",
                         brew="gowitness", go="github.com/sensepost/gowitness@latest", optional=True),

    # ── Utilities ──────────────────────────────────────────────
    "anew":        Tool("anew", "Append-only dedup for streaming pipelines",
                         go="github.com/tomnomnom/anew@latest"),
    "unfurl":      Tool("unfurl", "Pull apart URLs (domains/paths/params)",
                         go="github.com/tomnomnom/unfurl@latest", optional=True),
}

# Core tools = the recon backbone. If these are missing the pipeline degrades
# but still runs; optional tools simply enrich the results.
CORE_TOOLS = [n for n, t in TOOLS.items() if not t.optional]
OPTIONAL_TOOLS = [n for n, t in TOOLS.items() if t.optional]


# ─────────────────────────────────────────────────────────────
#  Wordlist registry — best public lists, merged for coverage
# ─────────────────────────────────────────────────────────────
# Sources chosen from what bug-bounty hunters actually run (assetnote,
# n0kovo, SecLists, trickest). We download what's reachable and merge+dedup.
WORDLIST_SOURCES = {
    "subdomains": [
        # n0kovo — statistically-generated, very high hit rate for its size
        "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_medium.txt",
        # SecLists classic top list
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
        # Assetnote best-dns (moderate slice via bbot list mirror)
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt",
    ],
    "permutations": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt",
    ],
    "resolvers": [
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
    ],
    # Small, curated, reliable set — used for RESOLUTION & VALIDATION (never the
    # 14k public list, which makes dnsx hang). Falls back to hardcoded below.
    "resolvers_trusted": [
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt",
    ],
}

# Baked-in trusted resolvers so resolution works even fully offline / if the
# download fails. Major anycast providers only.
TRUSTED_RESOLVERS_FALLBACK = [
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "8.8.8.8", "8.8.4.4",           # Google
    "9.9.9.9", "149.112.112.112",   # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "64.6.64.6", "64.6.65.6",       # Verisign
    "76.76.2.0", "76.76.10.0",      # Control D
]

# When only a "deep" run is requested we also pull these heavier lists.
WORDLIST_SOURCES_DEEP = {
    "subdomains": [
        "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_large.txt",
    ],
}


# ─────────────────────────────────────────────────────────────
#  Scan profiles
# ─────────────────────────────────────────────────────────────
@dataclass
class Profile:
    name: str
    description: str
    do_bruteforce: bool
    do_permutations: bool
    do_portscan: bool
    do_nse: bool                 # nmap scripting engine
    do_crawl: bool
    do_js: bool
    do_nuclei: bool
    do_screenshots: bool
    nuclei_severity: str         # comma list passed to -severity
    naabu_ports: str             # naabu -p / -top-ports
    max_crawl_hosts: int
    resolve_threads: int


PROFILES = {
    "quick": Profile(
        "quick", "Passive-only, fast. Subdomains + live check + light nuclei.",
        do_bruteforce=False, do_permutations=False, do_portscan=False, do_nse=False,
        do_crawl=False, do_js=False, do_nuclei=True, do_screenshots=False,
        nuclei_severity="critical,high", naabu_ports="top-100",
        max_crawl_hosts=0, resolve_threads=100),
    "standard": Profile(
        "standard", "Passive + active brute + ports + crawl + nuclei. Recommended.",
        do_bruteforce=True, do_permutations=True, do_portscan=True, do_nse=True,
        do_crawl=True, do_js=True, do_nuclei=True, do_screenshots=False,
        nuclei_severity="critical,high,medium", naabu_ports="top-1000",
        max_crawl_hosts=50, resolve_threads=150),
    "deep": Profile(
        "deep", "Everything: large wordlists, full ports, NSE, screenshots, full nuclei.",
        do_bruteforce=True, do_permutations=True, do_portscan=True, do_nse=True,
        do_crawl=True, do_js=True, do_nuclei=True, do_screenshots=True,
        nuclei_severity="critical,high,medium,low,info", naabu_ports="full",
        max_crawl_hosts=200, resolve_threads=200),
}
