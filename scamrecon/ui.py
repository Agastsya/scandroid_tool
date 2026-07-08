"""Terminal UI — a clean, professional look built on `rich`.

Everything the user sees (banner, phase headers, tables, progress, the final
summary) is funneled through here so the whole tool has one consistent style.
"""
from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn,
)
from rich.align import Align
from rich import box

console = Console()

BANNER = r"""
[bold red] ███████╗ ██████╗ █████╗ ███╗   ███╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗[/bold red]
[bold red] ██╔════╝██╔════╝██╔══██╗████╗ ████║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║[/bold red]
[bold red] ███████╗██║     ███████║██╔████╔██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║[/bold red]
[bold red] ╚════██║██║     ██╔══██║██║╚██╔╝██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║[/bold red]
[bold red] ███████║╚██████╗██║  ██║██║ ╚═╝ ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║[/bold red]
[bold red] ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bold red]
"""


def banner(version: str, platform_desc: str) -> None:
    console.print(BANNER)
    sub = Text.assemble(
        ("  Professional Reconnaissance Framework  ", "bold cyan"),
        (f"v{version}\n", "cyan"),
        ("  Passive + Active asset discovery • validated & report-ready\n", "dim white"),
        (f"  {platform_desc}", "magenta"),
    )
    console.print(Align.center(sub))
    console.print()


def phase_header(number: int, total: int, name: str, detail: str = "") -> None:
    title = Text.assemble(
        (f" PHASE {number}/{total} ", "bold white on blue"),
        ("  ", ""),
        (name, "bold cyan"),
    )
    if detail:
        title.append(f"\n {detail}", style="dim")
    console.print(Panel(title, box=box.HEAVY, border_style="blue", padding=(0, 1)))


def info(msg: str) -> None:
    console.print(f"[cyan][*][/cyan] {msg}")


def good(msg: str) -> None:
    console.print(f"[bold green][+][/bold green] {msg}")


def warn(msg: str) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def err(msg: str) -> None:
    console.print(f"[bold red][x][/bold red] {msg}")


def step(msg: str) -> None:
    console.print(f"    [dim]->[/dim] {msg}")


def result_count(tool: str, count: int, unit: str = "results") -> None:
    console.print(f"    [green]{tool:<16}[/green] [bold]{count:>7,}[/bold] [dim]{unit}[/dim]")


def rule(label: str = "") -> None:
    console.rule(f"[bold]{label}" if label else "", style="dim")


def progress_bar() -> Progress:
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def summary_table(title: str, rows: list[tuple[str, str]], accent: str = "cyan") -> None:
    t = Table(title=title, title_style=f"bold {accent}", box=box.ROUNDED, border_style=accent,
              show_header=False, padding=(0, 2))
    t.add_column("k", style="white")
    t.add_column("v", style=f"bold {accent}", justify="right")
    for k, v in rows:
        t.add_row(k, str(v))
    console.print(t)


def data_table(title: str, columns: list[str], rows: list[list], accent: str = "cyan",
               max_rows: int | None = 25) -> None:
    t = Table(title=title, title_style=f"bold {accent}", box=box.SIMPLE_HEAVY,
              border_style="dim", header_style=f"bold {accent}")
    for c in columns:
        t.add_column(c, overflow="fold")
    shown = rows if max_rows is None else rows[:max_rows]
    for r in shown:
        t.add_row(*[str(x) for x in r])
    console.print(t)
    if max_rows is not None and len(rows) > max_rows:
        console.print(f"    [dim]... and {len(rows) - max_rows:,} more (see report)[/dim]")


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
