"""Subprocess helpers — every external tool is launched through here.

Centralizing this gives us uniform timeout handling, output capture, graceful
"tool not installed" behavior, and easy dedup of line-based results.
"""
from __future__ import annotations

import concurrent.futures
import shutil
import subprocess
import threading
import time
from pathlib import Path

from . import config, ui

# ─────────────────────────────────────────────────────────────
#  Global deadline — a hard wall-clock budget for the whole run.
#  Every tool invocation is auto-capped to the time remaining, so no single
#  tool can ever run past the deadline and nothing hangs forever.
# ─────────────────────────────────────────────────────────────
_DEADLINE: float | None = None


def set_deadline(seconds: float | None) -> None:
    global _DEADLINE
    _DEADLINE = (time.time() + seconds) if seconds else None


def remaining() -> float | None:
    return None if _DEADLINE is None else max(0.0, _DEADLINE - time.time())


def expired() -> bool:
    r = remaining()
    return r is not None and r <= 0


def _cap(timeout: int) -> int:
    """Shrink a tool timeout so it can't exceed the remaining global budget."""
    r = remaining()
    if r is None:
        return timeout
    return max(1, min(int(timeout), int(r)))


# ─────────────────────────────────────────────────────────────
#  Tool ledger — records the outcome of every tool invocation so the report
#  can show exactly which tools ran, timed out, were skipped, or failed.
# ─────────────────────────────────────────────────────────────
_LEDGER: dict[str, dict] = {}
_LEDGER_LOCK = threading.Lock()


def reset_ledger() -> None:
    with _LEDGER_LOCK:
        _LEDGER.clear()


def record(tool: str, status: str, detail: str = "") -> None:
    with _LEDGER_LOCK:
        e = _LEDGER.setdefault(tool, {"ok": 0, "timeout": 0, "skipped": 0, "error": 0, "detail": ""})
        e[status] = e.get(status, 0) + 1
        if detail:
            e["detail"] = detail


def ledger() -> dict:
    with _LEDGER_LOCK:
        return {k: dict(v) for k, v in _LEDGER.items()}


def parallel(tasks, workers: int = 8):
    """Run zero-arg callables concurrently; return results in completion order.

    Exceptions in a task are swallowed (returned as None) so one failure never
    aborts the batch — matches the 'never let one tool kill the run' contract.
    """
    tasks = list(tasks)
    if not tasks:
        return []
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(tasks)))) as ex:
        futs = [ex.submit(t) for t in tasks]
        for f in concurrent.futures.as_completed(futs):
            try:
                out.append(f.result())
            except Exception:  # noqa: BLE001
                out.append(None)
    return out


def parallel_map(fn, items, workers: int = 8):
    """Map fn over items concurrently, preserving input order. Errors → None."""
    items = list(items)
    if not items:
        return []

    def _safe(x):
        try:
            return fn(x)
        except Exception:  # noqa: BLE001
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as ex:
        return list(ex.map(_safe, items))


class ToolResult:
    def __init__(self, ok: bool, lines: list[str], stderr: str = "", skipped: bool = False):
        self.ok = ok
        self.lines = lines
        self.stderr = stderr
        self.skipped = skipped

    def __bool__(self) -> bool:
        return self.ok


def resolve_binary(name: str) -> str | None:
    """Find a tool on PATH or in the go bin dir."""
    p = shutil.which(name)
    if p:
        return p
    cand = config.go_bin_dir() / name
    return str(cand) if cand.exists() else None


def run(cmd: list[str], timeout: int = 300, stdin_data: str | None = None,
        want_lines: bool = True) -> ToolResult:
    """Run a command, capture stdout. Auto-capped to the global deadline."""
    tool = cmd[0]
    binary = resolve_binary(tool)
    if binary is None:
        record(tool, "skipped", "not installed")
        return ToolResult(False, [], stderr=f"{tool} not installed", skipped=True)
    if expired():
        record(tool, "skipped", "time budget exceeded")
        return ToolResult(False, [], stderr="time budget exceeded", skipped=True)
    timeout = _cap(timeout)
    cmd = [binary] + cmd[1:]
    try:
        proc = subprocess.run(
            cmd, input=stdin_data, capture_output=True, text=True, timeout=timeout,
        )
        out = proc.stdout or ""
        lines = [l.strip() for l in out.splitlines() if l.strip()] if want_lines else []
        ok = proc.returncode == 0 or bool(lines)
        record(tool, "ok" if ok else "error")
        return ToolResult(ok, lines, stderr=proc.stderr or "")
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or "")
        if isinstance(partial, bytes):
            partial = partial.decode(errors="ignore")
        lines = [l.strip() for l in partial.splitlines() if l.strip()] if want_lines else []
        record(tool, "timeout", f"timed out after {timeout}s (partial results kept)")
        return ToolResult(bool(lines), lines, stderr=f"timeout after {timeout}s")
    except Exception as e:  # noqa: BLE001
        record(tool, "error", str(e)[:200])
        return ToolResult(False, [], stderr=str(e))


def stream(cmd: list[str], timeout: int = 600, on_line=None, quiet: bool = False) -> ToolResult:
    """Stream stdout line-by-line (long/verbose tools). Auto-capped to deadline.

    A watchdog thread hard-kills the process at the (capped) timeout so a tool
    that stops producing output can never wedge the pipeline.
    """
    tool = cmd[0]
    binary = resolve_binary(tool)
    if binary is None:
        record(tool, "skipped", "not installed")
        return ToolResult(False, [], stderr=f"{tool} not installed", skipped=True)
    if expired():
        record(tool, "skipped", "time budget exceeded")
        return ToolResult(False, [], stderr="time budget exceeded", skipped=True)
    timeout = _cap(timeout)
    cmd = [binary] + cmd[1:]
    lines: list[str] = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        # hard-kill watchdog: guarantees termination even if the read loop blocks
        killed = {"v": False}
        wd = threading.Thread(target=_sleep_kill, args=(proc, timeout, killed), daemon=True)
        wd.start()
        try:
            for raw in proc.stdout:  # type: ignore[union-attr]
                line = raw.rstrip("\n")
                if not line.strip():
                    continue
                lines.append(line.strip())
                if on_line:
                    on_line(line.strip())
                elif not quiet:
                    ui.step(line.strip())
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            killed["v"] = True
        if killed["v"]:
            record(tool, "timeout", f"timed out after {timeout}s (partial results kept)")
            return ToolResult(bool(lines), lines, stderr=f"timeout after {timeout}s")
        record(tool, "ok" if (proc.returncode == 0 or lines) else "error")
        return ToolResult(proc.returncode == 0 or bool(lines), lines)
    except Exception as e:  # noqa: BLE001
        record(tool, "error", str(e)[:200])
        return ToolResult(False, [], stderr=str(e))


def _sleep_kill(proc, timeout: int, killed: dict) -> None:
    """Watchdog: kill the process if it's still alive after `timeout` seconds."""
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        killed["v"] = True
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def write_lines(path: Path, items) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    uniq = sorted(dict.fromkeys(x for x in items if x))
    path.write_text("\n".join(uniq) + ("\n" if uniq else ""))
    return path


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text().splitlines() if l.strip()]
