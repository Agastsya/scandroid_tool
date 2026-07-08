"""Payload manager — best public payloads with offline-safe bundled fallbacks.

Same resilience contract as the recon wordlist manager: download the good lists
when the network allows, but never end up empty — the repo ships compact,
high-signal fallback payloads for LFI / XSS / SQLi / RCE so confirmation testing
works with zero connectivity.
"""
from __future__ import annotations

from pathlib import Path

import requests

from scamrecon import ui
from .config import PAYLOAD_DIR, PAYLOAD_SOURCES

DATA_DIR = Path(__file__).resolve().parent / "data"


def _download(url: str, timeout: int = 40) -> list[str]:
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return [l for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
    except Exception:  # noqa: BLE001
        return []


def _bundled(cat: str) -> list[str]:
    p = DATA_DIR / f"{cat}.txt"
    return [l for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def ensure(cat: str) -> Path:
    """Return a path to a payload file for `cat`, downloading/merging if needed."""
    dest = PAYLOAD_DIR / f"{cat}.txt"
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    merged: set[str] = set()
    for url in PAYLOAD_SOURCES.get(cat, []):
        merged.update(_download(url))
    if not merged:
        merged.update(_bundled(cat))
        if merged:
            ui.warn(f"{cat} payloads: using bundled fallback ({len(merged)})")
    if merged:
        dest.write_text("\n".join(sorted(merged)) + "\n")
    return dest


def ensure_all(cats: list[str]) -> dict[str, int]:
    stats = {}
    for cat in cats:
        p = ensure(cat)
        stats[cat] = sum(1 for _ in p.open()) if p.exists() else 0
        ui.result_count(f"{cat} payloads", stats[cat], "entries")
    return stats
