#!/usr/bin/env python3
"""
Kernel Anti-Cheat (Ubuntu).

Reads the running Linux kernel and verifies it matches the OFFICIAL Ubuntu kernel.
A machine PASSES only if:
  * the kernel flavour is an official Ubuntu flavour (generic / lowlatency / ...), and
  * the kernel version (major.minor.micro-abi) is >= the official version.

Anything else (custom flavour, downgraded/unknown kernel, tainted string) is treated
as tampering -> FAIL.

The official version can be supplied two ways:
  * --official-file PATH   read a pinned official version from disk (offline)
  * --crawl                fetch it live from Ubuntu's package page via crawl4ai

Exit code: 0 = PASS (trusted), 1 = FAIL (tampered / untrusted).
"""
from __future__ import annotations

import argparse
import platform
import re
import sys

# Official Ubuntu kernel flavours we accept. A tampered/custom kernel usually
# ships a different flavour tag (e.g. "-cheat", "-xanmod", "-tainted").
ALLOWED_FLAVOURS = {
    "generic",
    "lowlatency",
    "generic-hwe-24.04",
    "generic-hwe-22.04",
    "generic-hwe-20.04",
    "lowlatency-hwe-24.04",
    "lowlatency-hwe-22.04",
}

# Ubuntu kernel release strings look like: 6.8.0-45-generic
#                                          maj.min.mic-abi-flavour
KERNEL_RE = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<micro>\d+)-(?P<abi>\d+)-(?P<flavour>.+)$"
)


class ParseError(ValueError):
    pass


def parse_kernel(release: str):
    """Parse an Ubuntu kernel release string into a comparable structure."""
    release = release.strip()
    m = KERNEL_RE.match(release)
    if not m:
        raise ParseError(f"unrecognised kernel string: {release!r}")
    return {
        "raw": release,
        "version": (int(m["major"]), int(m["minor"]), int(m["micro"])),
        "abi": int(m["abi"]),
        "flavour": m["flavour"],
    }


def sort_key(k):
    """Order kernels by (version, abi) so we can compare 'newer or equal'."""
    return (*k["version"], k["abi"])


def get_running_kernel(override: str | None) -> str:
    if override:
        return override
    return platform.release()  # equivalent of `uname -r`


def get_official_from_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                return line
    raise ParseError(f"no official kernel version found in {path}")


def get_official_from_crawl(url: str) -> str:
    """Fetch the current official Ubuntu kernel version live using crawl4ai."""
    from crawler import fetch_official_kernel  # local module, lazy import

    return fetch_official_kernel(url)


def verify(running_str: str, official_str: str):
    """Return (passed: bool, reason: str)."""
    running = parse_kernel(running_str)
    official = parse_kernel(official_str)

    if running["flavour"] not in ALLOWED_FLAVOURS:
        return False, (
            f"flavour {running['flavour']!r} is not an official Ubuntu flavour "
            f"(expected one of: {', '.join(sorted(ALLOWED_FLAVOURS))})"
        )

    if sort_key(running) < sort_key(official):
        return False, (
            f"running kernel {running['raw']} is OLDER than official "
            f"{official['raw']} (downgrade / unofficial build)"
        )

    if sort_key(running) == sort_key(official):
        return True, f"exact match with official kernel {official['raw']}"

    return True, (
        f"running kernel {running['raw']} is newer than official "
        f"{official['raw']} (>= rule satisfied)"
    )


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Ubuntu kernel anti-cheat")
    p.add_argument("--kernel", help="override running kernel string (for testing)")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--official-file", help="path to pinned official kernel version")
    src.add_argument("--crawl", action="store_true", help="fetch official version via crawl4ai")
    p.add_argument(
        "--crawl-url",
        default="https://packages.ubuntu.com/noble/linux-image-generic",
        help="URL to crawl for the official kernel version",
    )
    args = p.parse_args(argv)

    running_str = get_running_kernel(args.kernel)

    try:
        if args.crawl:
            official_str = get_official_from_crawl(args.crawl_url)
            source = f"crawl4ai <{args.crawl_url}>"
        else:
            path = args.official_file or "ubuntu_official.txt"
            official_str = get_official_from_file(path)
            source = f"file <{path}>"
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] could not obtain official kernel: {exc}", file=sys.stderr)
        return 2

    print("=" * 60)
    print(" Ubuntu Kernel Anti-Cheat")
    print("=" * 60)
    print(f" running kernel  : {running_str}")
    print(f" official kernel : {official_str}   (source: {source})")

    try:
        passed, reason = verify(running_str, official_str)
    except ParseError as exc:
        print(f" verdict         : \033[31mFAIL\033[0m (unparseable: {exc})")
        print("=" * 60)
        return 1

    if passed:
        print(f" verdict         : \033[32mPASS\033[0m — {reason}")
        print("=" * 60)
        return 0

    print(f" verdict         : \033[31mFAIL\033[0m — {reason}")
    print(" -> possible kernel tampering / cheating detected")
    print("=" * 60)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
