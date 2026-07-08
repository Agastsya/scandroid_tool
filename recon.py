#!/usr/bin/env python3
"""ScamRecon — professional reconnaissance framework.

Usage:
  python3 recon.py --install                 # install/verify the toolchain
  python3 recon.py -d example.com            # standard recon on a domain
  python3 recon.py -d example.com -p deep    # deep recon (everything)
  python3 recon.py -d example.com -p quick   # fast passive-only pass
  python3 recon.py                           # interactive menu

Only scan domains you are authorized to test.
"""
from __future__ import annotations

import argparse
import sys

from scamrecon import __version__, config, ui, installer, pipeline, wordlists
from scamrecon.config import PLATFORM, PROFILES, TOOLS


def _platform_desc() -> str:
    return (f"{PLATFORM.distro.title()} · {PLATFORM.arch} · "
            f"pkg:{PLATFORM.pkg_manager or 'none'} · py{sys.version_info.major}.{sys.version_info.minor}")


def cmd_install(optional: bool = True) -> None:
    installer.install_all(include_optional=optional)
    ui.rule("VERIFICATION PASS")
    status = installer.verify(include_optional=optional)
    missing_core = [n for n in config.CORE_TOOLS if not status.get(n, False)]
    present = sum(1 for v in status.values() if v)
    ui.summary_table("Verification", [
        ("Tools present", f"{present}/{len(status)}"),
        ("Core tools OK", "yes" if not missing_core else f"NO — missing {', '.join(missing_core)}"),
    ], accent="green" if not missing_core else "red")
    if missing_core:
        ui.warn("Some core tools are still missing — re-run --install or install them manually.")
    else:
        ui.good("All core tools verified. You're ready to run recon.")


def _tool_status_table() -> None:
    from rich.table import Table
    from rich import box
    t = Table(title="Toolchain", box=box.ROUNDED, border_style="cyan", header_style="bold cyan")
    t.add_column("Tool"); t.add_column("Purpose", overflow="fold"); t.add_column("Status", justify="center")
    for name, tool in TOOLS.items():
        ok = tool.installed()
        tag = " [dim](opt)[/dim]" if tool.optional else ""
        t.add_row(name + tag, tool.purpose,
                  "[green]✓[/green]" if ok else "[red]✗[/red]")
    ui.console.print(t)


def interactive() -> None:
    while True:
        ui.console.print()
        ui.summary_table("ScamRecon — Menu", [
            ("1", "Run recon on a domain"),
            ("2", "Install / update toolchain"),
            ("3", "Verify toolchain status"),
            ("4", "Download / refresh wordlists"),
            ("5", "Exit"),
        ], accent="cyan")
        choice = ui.console.input("[bold cyan]  choice > [/bold cyan]").strip()

        if choice == "1":
            domain = ui.console.input("[yellow]  target domain > [/yellow]").strip()
            if not domain:
                ui.err("no domain given"); continue
            ui.console.print("[dim]  profiles: quick (passive) · standard (recommended) · deep (everything)[/dim]")
            prof = ui.console.input("[yellow]  profile [standard] > [/yellow]").strip() or "standard"
            if prof not in PROFILES:
                ui.warn(f"unknown profile, using standard"); prof = "standard"
            pipeline.run(domain, prof)
        elif choice == "2":
            cmd_install()
        elif choice == "3":
            _tool_status_table()
        elif choice == "4":
            deep = ui.console.input("[yellow]  deep lists? (y/N) > [/yellow]").strip().lower() == "y"
            wordlists.ensure_wordlists(deep=deep, force=True)
        elif choice == "5":
            ui.good("bye"); break
        else:
            ui.err("invalid choice")


def main() -> None:
    ap = argparse.ArgumentParser(description="ScamRecon — professional recon framework",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-d", "--domain", help="target root domain")
    ap.add_argument("-p", "--profile", default="standard", choices=list(PROFILES.keys()),
                    help="scan profile (default: standard)")
    ap.add_argument("--install", action="store_true", help="install & verify the toolchain")
    ap.add_argument("--core-only", action="store_true", help="with --install: skip optional tools")
    ap.add_argument("--deep-wordlists", action="store_true", help="also fetch large brute-force lists")
    ap.add_argument("--max-time", type=int, default=120, metavar="MIN",
                    help="hard wall-clock budget in minutes (default 120); the run always reports")
    ap.add_argument("--status", action="store_true", help="show toolchain status and exit")
    ap.add_argument("--refresh-wordlists", action="store_true", help="re-download & merge wordlists")
    args = ap.parse_args()

    ui.banner(__version__, _platform_desc())

    if args.install:
        cmd_install(optional=not args.core_only); return
    if args.status:
        _tool_status_table(); return
    if args.refresh_wordlists:
        wordlists.ensure_wordlists(deep=args.deep_wordlists, force=True); return
    if args.domain:
        pipeline.run(args.domain, args.profile, deep_wordlists=args.deep_wordlists,
                     max_minutes=args.max_time); return

    interactive()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        ui.console.print("\n[yellow]interrupted[/yellow]")
        sys.exit(130)
