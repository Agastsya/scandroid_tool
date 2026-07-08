"""Cross-platform toolchain installer for Kali, Parrot, and macOS (Apple Silicon).

Strategy per tool, in order of preference for the current platform:
  macOS  : brew  -> go install -> pip -> git
  Linux  : apt   -> go install -> pip -> git

Idempotent: anything already on PATH (or in ~/go/bin) is skipped. Prints a
final status table so you can see exactly what's present and what failed.
"""
from __future__ import annotations

import os
import subprocess
import shutil
from pathlib import Path

from . import config, ui
from .config import PLATFORM, TOOLS, Tool
from rich.table import Table
from rich import box


def _run(cmd: list[str], timeout: int = 900) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, (p.stdout + p.stderr)[-2000:]
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def ensure_prereqs() -> dict[str, bool]:
    """Make sure the package managers / language toolchains we rely on exist."""
    status: dict[str, bool] = {}
    ui.info("Checking prerequisites (brew/apt, go, pip, git)...")

    if PLATFORM.is_mac:
        status["brew"] = _have("brew")
        if not status["brew"]:
            ui.warn("Homebrew missing. Install it from https://brew.sh then re-run --install")
    else:
        status["apt"] = _have("apt-get") or _have("apt")

    status["go"] = _have("go")
    status["git"] = _have("git")
    status["pip"] = True
    try:
        subprocess.run(["python3", "-m", "pip", "--version"], capture_output=True, check=True)
    except Exception:
        status["pip"] = False

    # Go is essential — a huge share of the toolchain is go install.
    if not status["go"]:
        ui.warn("Go is not installed — many tools cannot be built.")
        if PLATFORM.is_mac and status.get("brew"):
            ui.info("Installing go via brew...")
            ok, _ = _run(["brew", "install", "go"])
            status["go"] = ok
        elif PLATFORM.is_linux and status.get("apt"):
            ui.info("Installing go via apt (sudo)...")
            ok, _ = _run(["sudo", "apt-get", "install", "-y", "golang-go"])
            status["go"] = ok

    # Python libraries the framework itself needs (rich, requests, jinja2,
    # dnspython, reportlab for PDF). Installed into the interpreter running this.
    ui.info("Installing Python dependencies (rich, requests, jinja2, dnspython, reportlab)...")
    req = config.BASE_DIR / "requirements.txt"
    pip_cmd = ["python3", "-m", "pip", "install", "--quiet", "--break-system-packages"]
    if req.exists():
        ok, out = _run(pip_cmd + ["-r", str(req)])
    else:
        ok, out = _run(pip_cmd + ["rich", "requests", "jinja2", "dnspython", "reportlab"])
    if not ok:  # retry without --break-system-packages for non-PEP668 envs
        ok, out = _run([c for c in pip_cmd if c != "--break-system-packages"] +
                       (["-r", str(req)] if req.exists() else
                        ["rich", "requests", "jinja2", "dnspython", "reportlab"]))
    status["python-deps"] = ok
    (ui.good if ok else ui.warn)(f"python deps: {'installed' if ok else 'check manually'}")

    for k, v in status.items():
        (ui.good if v else ui.err)(f"prereq {k}: {'ok' if v else 'MISSING'}")
    return status


def _install_one(tool: Tool) -> tuple[str, str]:
    """Return (status, method). status in installed/skipped/failed."""
    if tool.installed():
        return "present", "already"

    # Preferred package manager for the platform
    if PLATFORM.is_mac and tool.brew:
        ok, _ = _run(["brew", "install", tool.brew])
        if ok and tool.installed():
            return "installed", "brew"
    if PLATFORM.is_linux and tool.apt:
        ok, _ = _run(["sudo", "apt-get", "install", "-y", tool.apt])
        if ok and tool.installed():
            return "installed", "apt"

    # go install
    if tool.go and _have("go"):
        env = os.environ.copy()
        env["GOFLAGS"] = "-buildvcs=false"
        try:
            p = subprocess.run(["go", "install", "-v", tool.go], capture_output=True,
                               text=True, timeout=900, env=env)
            if p.returncode == 0 and tool.installed():
                return "installed", "go"
        except Exception:
            pass

    # pip
    if tool.pip:
        ok, _ = _run(["python3", "-m", "pip", "install", "--break-system-packages",
                      "--quiet", tool.pip])
        if ok and tool.installed():
            return "installed", "pip"

    # git-clone script tools
    if tool.git:
        dest = config.BASE_DIR / "tools" / tool.name
        if not dest.exists():
            _run(["git", "clone", "--depth", "1", tool.git, str(dest)])
        if dest.exists():
            return "installed", "git"

    # findomain / special binaries
    if tool.binary and PLATFORM.is_mac and tool.brew:
        ok, _ = _run(["brew", "install", tool.brew])
        if ok and tool.installed():
            return "installed", "brew"

    return "failed", "-"


def install_all(include_optional: bool = True) -> dict[str, tuple[str, str]]:
    ui.phase_header(0, 0, "Toolchain Installation",
                    f"{PLATFORM.distro} / {PLATFORM.arch} — pkg: {PLATFORM.pkg_manager}")
    ensure_prereqs()

    names = list(TOOLS.keys()) if include_optional else config.CORE_TOOLS
    results: dict[str, tuple[str, str]] = {}

    with ui.progress_bar() as prog:
        task = prog.add_task("Installing tools", total=len(names))
        for name in names:
            tool = TOOLS[name]
            prog.update(task, description=f"Installing [cyan]{name}[/cyan]")
            results[name] = _install_one(tool)
            prog.advance(task)

    _print_matrix(results)
    _path_hint()
    return results


def _print_matrix(results: dict[str, tuple[str, str]]) -> None:
    t = Table(title="Toolchain Status", box=box.ROUNDED, border_style="cyan",
              header_style="bold cyan", title_style="bold cyan")
    t.add_column("Tool")
    t.add_column("Purpose", overflow="fold")
    t.add_column("Status", justify="center")
    t.add_column("Via", justify="center")
    icon = {"present": "[green]✓ present[/green]", "installed": "[bold green]✓ installed[/bold green]",
            "failed": "[bold red]✗ failed[/bold red]", "skipped": "[yellow]- skipped[/yellow]"}
    for name, (status, via) in results.items():
        tool = TOOLS[name]
        tag = " [dim](optional)[/dim]" if tool.optional else ""
        t.add_row(name + tag, tool.purpose, icon.get(status, status), via)
    ui.console.print(t)

    present = sum(1 for s, _ in results.values() if s in ("present", "installed"))
    failed = [n for n, (s, _) in results.items() if s == "failed"]
    ui.good(f"{present}/{len(results)} tools available")
    if failed:
        core_failed = [f for f in failed if f in config.CORE_TOOLS]
        if core_failed:
            ui.err(f"CORE tools failed: {', '.join(core_failed)} — recon quality will suffer")
        opt_failed = [f for f in failed if f not in config.CORE_TOOLS]
        if opt_failed:
            ui.warn(f"Optional tools failed (non-blocking): {', '.join(opt_failed)}")


def _path_hint() -> None:
    go_bin = config.go_bin_dir()
    if str(go_bin) not in os.environ.get("PATH", ""):
        ui.warn(f"Add Go binaries to PATH so tools are found in new shells:")
        shell_rc = "~/.zshrc" if PLATFORM.is_mac else "~/.bashrc"
        ui.console.print(f'    [cyan]echo \'export PATH="$PATH:{go_bin}"\' >> {shell_rc}[/cyan]')


def verify(include_optional: bool = True) -> dict[str, bool]:
    """Second-pass verification — re-check every tool actually resolves."""
    names = list(TOOLS.keys()) if include_optional else config.CORE_TOOLS
    status = {name: TOOLS[name].installed() for name in names}
    missing_core = [n for n in config.CORE_TOOLS if not status.get(n, False)]
    return status
