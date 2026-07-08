"""VAPT toolchain installer — reuses ScamRecon's install engine.

Same idempotent, cross-platform strategy (brew/apt → go → pip → git) driven by
this package's tool registry. Also fetches/updates nuclei templates, which the
DAST and tag scans depend on.
"""
from __future__ import annotations

import subprocess

from scamrecon import ui
from scamrecon.installer import ensure_prereqs, _install_one, _print_matrix, _path_hint, _run
from . import config
from .config import TOOLS


def install_all(include_optional: bool = True) -> dict:
    ui.phase_header(0, 0, "VAPT Toolchain Installation",
                    f"{config.PLATFORM.distro} / {config.PLATFORM.arch}")
    ensure_prereqs()
    names = list(TOOLS.keys()) if include_optional else config.CORE_TOOLS
    results = {}
    with ui.progress_bar() as prog:
        task = prog.add_task("Installing VAPT tools", total=len(names))
        for name in names:
            prog.update(task, description=f"Installing [cyan]{name}[/cyan]")
            results[name] = _install_one(TOOLS[name])
            prog.advance(task)
    _print_matrix_vapt(results)
    _update_nuclei_templates()
    _path_hint()
    return results


def _print_matrix_vapt(results: dict) -> None:
    from rich.table import Table
    from rich import box
    t = Table(title="VAPT Toolchain Status", box=box.ROUNDED, border_style="magenta",
              header_style="bold magenta", title_style="bold magenta")
    t.add_column("Tool"); t.add_column("Purpose", overflow="fold")
    t.add_column("Status", justify="center"); t.add_column("Via", justify="center")
    icon = {"present": "[green]✓ present[/green]", "installed": "[bold green]✓ installed[/bold green]",
            "failed": "[bold red]✗ failed[/bold red]"}
    for name, (status, via) in results.items():
        tool = TOOLS[name]
        tag = " [dim](opt)[/dim]" if tool.optional else ""
        t.add_row(name + tag, tool.purpose, icon.get(status, status), via)
    ui.console.print(t)
    present = sum(1 for s, _ in results.values() if s in ("present", "installed"))
    ui.good(f"{present}/{len(results)} VAPT tools available")
    core_missing = [n for n in config.CORE_TOOLS if results.get(n, ("failed",))[0] == "failed"]
    if core_missing:
        ui.err(f"CORE tools missing: {', '.join(core_missing)} — confirmation coverage reduced")


def _update_nuclei_templates() -> None:
    if not TOOLS["nuclei"].installed():
        return
    ui.info("Updating nuclei templates (powers the DAST + host-level tag scans)...")
    ok, _ = _run(["nuclei", "-update-templates", "-silent"], timeout=400)
    (ui.good if ok else ui.warn)("nuclei templates " + ("updated" if ok else "update skipped"))
    # fuzzing-templates: the DAST payloads used for confirmed injection findings
    import shutil
    from pathlib import Path
    ft = config.FUZZING_TEMPLATES
    if ft.exists():
        ui.good("fuzzing-templates present")
    elif shutil.which("git"):
        ui.info("Cloning projectdiscovery/fuzzing-templates for DAST...")
        ok, _ = _run(["git", "clone", "--depth", "1",
                      "https://github.com/projectdiscovery/fuzzing-templates",
                      str(ft)], timeout=300)
        (ui.good if ok else ui.warn)("fuzzing-templates " + ("cloned" if ok else "clone skipped"))


def verify(include_optional: bool = True) -> dict:
    names = list(TOOLS.keys()) if include_optional else config.CORE_TOOLS
    return {n: TOOLS[n].installed() for n in names}
