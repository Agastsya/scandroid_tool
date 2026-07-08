"""Wordlist manager — fetch the best public lists and merge them.

For subdomain brute-forcing, no single list wins; hunters merge several. We pull
n0kovo (statistical), SecLists top-1M, and bitquark, then dedupe into one list.
Resolvers come from the trickest public set. Everything is cached on disk so we
only download once.
"""
from __future__ import annotations

from pathlib import Path

import requests

from . import config, ui
from .config import (WORDLIST_DIR, RESOLVERS_FILE, RESOLVERS_TRUSTED_FILE,
                     SUBS_WORDLIST, PERMUTATION_WORDLIST)

# Repo-bundled fallback lists so the tool works fully offline / when the flaky
# network can't reach GitHub. Used to seed downloads and as a hard floor.
DATA_DIR = Path(__file__).resolve().parent / "data"
BUNDLED = {
    SUBS_WORDLIST.name: DATA_DIR / "subdomains.txt",
    PERMUTATION_WORDLIST.name: DATA_DIR / "permutations.txt",
}


def _download(url: str, timeout: int = 60) -> list[str]:
    try:
        resp = requests.get(url, timeout=timeout, stream=True)
        resp.raise_for_status()
        return [l.strip() for l in resp.text.splitlines() if l.strip() and not l.startswith("#")]
    except Exception as e:  # noqa: BLE001
        ui.warn(f"could not fetch {url.split('/')[-1]}: {e}")
        return []


def _bundled_words(dest_name: str) -> set[str]:
    p = BUNDLED.get(dest_name)
    if p and p.exists():
        return {l.strip() for l in p.read_text().splitlines() if l.strip()}
    return set()


def _merge_to(dest, sources: list[str], label: str) -> int:
    merged: set[str] = set()
    # start from any existing cached content — never lose good data
    if dest.exists() and dest.stat().st_size > 0:
        merged.update(l.strip() for l in dest.read_text().splitlines() if l.strip())
    added_before = len(merged)
    for url in sources:
        name = url.split("/")[-1]
        ui.step(f"fetching {name} ...")
        words = _download(url)
        merged.update(words)
        ui.result_count(name[:16], len(words), "words")

    # Never write an empty file: if downloads yielded nothing and there was no
    # cache, seed from the repo-bundled fallback so brute-force still works.
    if not merged:
        merged = _bundled_words(dest.name)
        if merged:
            ui.warn(f"{label}: downloads unavailable — using bundled fallback "
                    f"({len(merged):,} entries)")
        else:
            ui.err(f"{label}: no data available (downloads failed, no fallback)")
            return 0
    dest.write_text("\n".join(sorted(merged)) + "\n")
    ui.good(f"{label}: {len(merged):,} unique entries (+{len(merged)-added_before:,}) -> {dest.name}")
    return len(merged)


def ensure_trusted_resolvers() -> str:
    """Guarantee a small, reliable resolver list exists for resolution/validation.

    This is cheap and always safe to call (even in the quick profile). Never
    returns the huge public list, which makes dnsx hang.
    """
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    if RESOLVERS_TRUSTED_FILE.exists() and RESOLVERS_TRUSTED_FILE.stat().st_size > 0:
        return str(RESOLVERS_TRUSTED_FILE)
    resolvers: list[str] = []
    for url in config.WORDLIST_SOURCES.get("resolvers_trusted", []):
        resolvers = _download(url, timeout=20)
        if resolvers:
            break
    if not resolvers:
        resolvers = config.TRUSTED_RESOLVERS_FALLBACK
        ui.warn("using built-in trusted resolvers (download unavailable)")
    # keep it small and sane — trusted lists are ~30 entries; cap defensively
    resolvers = [r for r in resolvers if r][:100]
    RESOLVERS_TRUSTED_FILE.write_text("\n".join(resolvers) + "\n")
    ui.good(f"trusted resolvers ready: {len(resolvers)} entries")
    return str(RESOLVERS_TRUSTED_FILE)


def ensure_wordlists(deep: bool = False, force: bool = False) -> dict:
    ui.info("Preparing wordlists (merged from best public sources)...")
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)

    if force:
        for f in (SUBS_WORDLIST, PERMUTATION_WORDLIST, RESOLVERS_FILE, RESOLVERS_TRUSTED_FILE):
            if f.exists():
                f.unlink()

    stats = {}
    ensure_trusted_resolvers()

    if not SUBS_WORDLIST.exists() or force:
        sources = list(config.WORDLIST_SOURCES["subdomains"])
        if deep:
            sources += config.WORDLIST_SOURCES_DEEP.get("subdomains", [])
        stats["subdomains"] = _merge_to(SUBS_WORDLIST, sources, "subdomain wordlist")
    else:
        stats["subdomains"] = sum(1 for _ in SUBS_WORDLIST.open())
        ui.good(f"subdomain wordlist cached: {stats['subdomains']:,} entries")

    if not PERMUTATION_WORDLIST.exists() or force:
        stats["permutations"] = _merge_to(
            PERMUTATION_WORDLIST, config.WORDLIST_SOURCES["permutations"], "permutation wordlist")
    else:
        stats["permutations"] = sum(1 for _ in PERMUTATION_WORDLIST.open())

    if not RESOLVERS_FILE.exists() or force:
        stats["resolvers"] = _merge_to(
            RESOLVERS_FILE, config.WORDLIST_SOURCES["resolvers"], "DNS resolvers")
    else:
        stats["resolvers"] = sum(1 for _ in RESOLVERS_FILE.open())
        ui.good(f"resolvers cached: {stats['resolvers']:,} entries")

    return stats
