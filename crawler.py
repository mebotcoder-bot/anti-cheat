#!/usr/bin/env python3
"""
crawl4ai-based fetcher for the official Ubuntu kernel version.

Crawls an Ubuntu package page (e.g. the linux-image-generic meta-package page)
and extracts the current official kernel version string like `6.8.0-45-generic`.

Used by anticheat.py when run with `--crawl`. Kept separate so the core
anti-cheat logic works fully offline (via a pinned official file) for testing.
"""
from __future__ import annotations

import asyncio
import re

# Match a full Ubuntu kernel release token anywhere in the crawled page text.
_KERNEL_TOKEN = re.compile(r"\b(\d+\.\d+\.\d+-\d+-generic)\b")

# The meta-package version looks like `6.8.0-45.45` and maps to `6.8.0-45-generic`.
_META_VERSION = re.compile(r"\b(\d+\.\d+\.\d+)-(\d+)\.\d+\b")


def _extract_kernel(text: str) -> str:
    """Pick the highest official kernel version referenced on the page."""
    candidates: set[tuple[tuple[int, int, int, int], str]] = set()

    for tok in _KERNEL_TOKEN.findall(text):
        maj, minr, mic, abi = re.match(
            r"(\d+)\.(\d+)\.(\d+)-(\d+)-generic", tok
        ).groups()
        key = (int(maj), int(minr), int(mic), int(abi))
        candidates.add((key, tok))

    for maj_min_mic, abi in _META_VERSION.findall(text):
        maj, minr, mic = maj_min_mic.split(".")
        key = (int(maj), int(minr), int(mic), int(abi))
        candidates.add((key, f"{maj_min_mic}-{abi}-generic"))

    if not candidates:
        raise ValueError("no Ubuntu kernel version found on crawled page")

    return max(candidates, key=lambda c: c[0])[1]


async def _crawl(url: str) -> str:
    from crawl4ai import AsyncWebCrawler  # imported lazily; optional dependency

    async with AsyncWebCrawler() as crawler:
        result = await crawler.arun(url=url)
        if not result.success:
            raise RuntimeError(f"crawl4ai failed to fetch {url}: {result.error_message}")
        # markdown is the cleaned text representation of the page
        text = result.markdown or result.cleaned_html or ""
        return _extract_kernel(text)


def fetch_official_kernel(url: str) -> str:
    """Synchronous entry point: returns e.g. '6.8.0-45-generic'."""
    return asyncio.run(_crawl(url))


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else (
        "https://packages.ubuntu.com/noble/linux-image-generic"
    )
    print(fetch_official_kernel(target))
