#!/usr/bin/env python3
"""ScamVapt — confirmation-first vulnerability assessment framework.

Consumes ScamRecon output and confirms ONLY real, tool-proven critical/high vulns
(SQLi, XSS, LFI, RCE, SSRF, open-redirect, CRLF). Zero-false-positive by design.

Usage:
  python3 vapt.py --install                       # install & verify the toolchain
  python3 vapt.py -d example.com                   # FULL: recon (find+validate subdomains) → VAPT
  python3 vapt.py -d example.com -p deep           # deep recon + deep VAPT
  python3 vapt.py --from-recon recon_output        # skip recon, reuse an existing recon run
  python3 vapt.py -u "https://site/p?id=1"         # test a single URL
  python3 vapt.py -l urls.txt                      # test a list of URLs
  python3 vapt.py                                  # interactive menu

Only test targets you are explicitly authorized to assess.
"""
from __future__ import annotations

import argparse
import sys

from scamrecon import ui
from scamvapt import __version__, config, installer, pipeline, payloads
from scamvapt.config import PLATFORM, PROFILES, TOOLS


def _platform_desc() -> str:
    return (f"{PLATFORM.distro.title()} · {PLATFORM.arch} · "
            f"py{sys.version_info.major}.{sys.version_info.minor}")


def _banner() -> None:
    ui.console.print(r"""
[bold red] ██╗   ██╗ █████╗ ██████╗ ████████╗[/bold red]
[bold red] ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝[/bold red]
[bold red] ██║   ██║███████║██████╔╝   ██║   [/bold red]
[bold red] ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   [/bold red]
[bold red]  ╚████╔╝ ██║  ██║██║        ██║   [/bold red]
[bold red]   ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝   [/bold red]""")
    ui.console.print(f"  [bold magenta]ScamVapt[/bold magenta] v{__version__} — "
                     f"confirmation-first VAPT  [dim]{_platform_desc()}[/dim]")
    ui.console.print("  [dim]zero false positives · only tool-proven vulnerabilities are reported[/dim]\n")


# vapt profile → recon profile. Must crawl for URLs/params (the `quick` recon
# profile is passive-only and finds no parameters), so `fast` maps to `standard`.
_RECON_PROFILE = {"fast": "standard", "standard": "standard", "deep": "deep"}


def run_domain(domain: str, profile: str, max_minutes: int):
    """FULL chain: recon a domain (find + validate subdomains & URLs) → VAPT them.

    This is what you want when you only have a domain: it discovers the whole
    attack surface (passive + active subdomain enum, live-host validation, URL /
    parameter discovery) and then runs the confirmation-first VAPT scanners over
    everything found. The time budget is split between the two stages.
    """
    from scamrecon import pipeline as recon_pipeline

    recon_prof = _RECON_PROFILE.get(profile, "standard")
    # split the budget: recon gets ~40%, VAPT ~60% (each at least 5 min)
    recon_min = max(5, int(max_minutes * 0.4))
    vapt_min = max(5, max_minutes - recon_min)

    ui.rule(f"STAGE 1/2 · RECON on {domain}  (≤{recon_min}m, profile {recon_prof})")
    ui.info("Discovering subdomains (passive + active) and validating live hosts...")
    rstate = recon_pipeline.run(domain, recon_prof, max_minutes=recon_min)
    recon_dir = rstate.outdir

    ui.console.print()
    ui.rule(f"STAGE 2/2 · VAPT on {len(rstate.live)} live host(s) from recon  (≤{vapt_min}m)")
    if not rstate.live and not rstate.resolved:
        ui.err("recon found no live hosts to test — check the domain / network and retry.")
        return
    pipeline.run(recon=str(recon_dir), profile_name=profile, max_minutes=vapt_min, label=domain)


def cmd_install(optional=True) -> None:
    installer.install_all(include_optional=optional)
    ui.rule("VERIFICATION PASS")
    status = installer.verify(optional)
    missing_core = [n for n in config.CORE_TOOLS if not status.get(n)]
    present = sum(1 for v in status.values() if v)
    ui.summary_table("Verification", [
        ("Tools present", f"{present}/{len(status)}"),
        ("Core OK", "yes" if not missing_core else f"NO — {', '.join(missing_core)}"),
    ], accent="green" if not missing_core else "red")
    (ui.good if not missing_core else ui.warn)(
        "All core VAPT tools verified." if not missing_core
        else "Some core tools missing — re-run --install or install manually.")


def _status_table() -> None:
    from rich.table import Table
    from rich import box
    t = Table(title="VAPT Toolchain", box=box.ROUNDED, border_style="magenta", header_style="bold magenta")
    t.add_column("Tool"); t.add_column("Purpose", overflow="fold"); t.add_column("Status", justify="center")
    for name, tool in TOOLS.items():
        tag = " [dim](opt)[/dim]" if tool.optional else ""
        t.add_row(name + tag, tool.purpose, "[green]✓[/green]" if tool.installed() else "[red]✗[/red]")
    ui.console.print(t)


def interactive() -> None:
    while True:
        ui.summary_table("ScamVapt — Menu", [
            ("1", "Scan a DOMAIN  (recon → find subdomains → VAPT)  ← start here"),
            ("2", "Test an existing recon run (--from-recon)"),
            ("3", "Test a single URL"),
            ("4", "Test a URL list file"),
            ("5", "Install / update toolchain"),
            ("6", "Toolchain status"),
            ("7", "Exit"),
        ], accent="magenta")
        c = ui.console.input("[bold magenta]  choice > [/bold magenta]").strip()
        prof = "standard"
        if c in ("1", "2", "3", "4"):
            ui.console.print("[dim]  profiles: fast · standard (recommended) · deep[/dim]")
            prof = ui.console.input("[yellow]  profile [standard] > [/yellow]").strip() or "standard"
            if prof not in PROFILES:
                prof = "standard"
        if c == "1":
            dom = ui.console.input("[yellow]  target domain (e.g. example.com) > [/yellow]").strip()
            mt = ui.console.input("[yellow]  max time in minutes [120] > [/yellow]").strip()
            if dom:
                run_domain(dom, prof, int(mt) if mt.isdigit() else 120)
        elif c == "2":
            path = ui.console.input("[yellow]  recon output dir or report.json > [/yellow]").strip()
            if path:
                pipeline.run(recon=path, profile_name=prof)
        elif c == "3":
            u = ui.console.input("[yellow]  target URL > [/yellow]").strip()
            if u:
                pipeline.run(url=u, profile_name=prof)
        elif c == "4":
            f = ui.console.input("[yellow]  path to URL list > [/yellow]").strip()
            if f:
                pipeline.run(url_file=f, profile_name=prof)
        elif c == "5":
            cmd_install()
        elif c == "6":
            _status_table()
        elif c == "7":
            ui.good("bye"); break
        else:
            ui.err("invalid choice")


def main() -> None:
    ap = argparse.ArgumentParser(description="ScamVapt — confirmation-first VAPT framework",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-d", "--domain", help="target domain — runs recon (find+validate subdomains) then VAPT")
    ap.add_argument("--from-recon", help="recon_output dir or report.json to consume (skip recon)")
    ap.add_argument("-u", "--url", help="single target URL")
    ap.add_argument("-l", "--list", dest="url_file", help="file with target URLs")
    ap.add_argument("-p", "--profile", default="standard", choices=list(PROFILES.keys()))
    ap.add_argument("--max-time", type=int, default=120, metavar="MIN",
                    help="hard wall-clock budget in minutes (default 120); always reports")
    ap.add_argument("--install", action="store_true", help="install & verify the toolchain")
    ap.add_argument("--core-only", action="store_true", help="with --install: skip optional tools")
    ap.add_argument("--status", action="store_true", help="show toolchain status and exit")
    args = ap.parse_args()

    _banner()
    if args.install:
        cmd_install(optional=not args.core_only); return
    if args.status:
        _status_table(); return
    if args.domain:
        run_domain(args.domain, args.profile, args.max_time); return
    if args.from_recon:
        pipeline.run(recon=args.from_recon, profile_name=args.profile, max_minutes=args.max_time); return
    if args.url:
        pipeline.run(url=args.url, profile_name=args.profile, max_minutes=args.max_time); return
    if args.url_file:
        pipeline.run(url_file=args.url_file, profile_name=args.profile, max_minutes=args.max_time); return
    interactive()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        ui.console.print("\n[yellow]interrupted[/yellow]")
        sys.exit(130)
