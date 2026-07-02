#!/usr/bin/env python3
"""
Integrity-signal collectors that run on the client machine.

Each collector reads a real Linux source (procfs/sysfs/efivars/kmod). On a
non-Linux dev box the sources are absent, so collectors degrade to
{"available": False}. A `sim` overlay lets us inject tampered/clean values to
exercise the full pipeline off-target (used by the test harness).

None of these are trusted on their own — they are inputs the server scores. The
kernel module (client/kmod/acheat.c) is what makes the harder signals (hidden
modules, syscall-table hooks) trustworthy in production; the userspace versions
here are the best-effort fallback.
"""
from __future__ import annotations

import os
import subprocess
import sys

# Reuse the Ubuntu kernel parsing/policy already written and tested.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from anticheat import ALLOWED_FLAVOURS, parse_kernel  # noqa: E402


def _read(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def collect_kernel() -> dict:
    import platform

    release = platform.release()
    info = {"release": release}
    try:
        parsed = parse_kernel(release)
        info.update(
            base_version=".".join(map(str, parsed["version"])),
            abi=parsed["abi"],
            flavour=parsed["flavour"],
            flavour_official=parsed["flavour"] in ALLOWED_FLAVOURS,
        )
    except Exception:  # noqa: BLE001 — non-Ubuntu / non-Linux release string
        info["flavour_official"] = None
    return info


def collect_taint() -> dict:
    """/proc/sys/kernel/tainted: nonzero => out-of-tree/forced modules, etc."""
    raw = _read("/proc/sys/kernel/tainted")
    if raw is None:
        return {"available": False}
    value = int(raw)
    return {"available": True, "value": value, "clean": value == 0}


def collect_secure_boot() -> dict:
    """Secure Boot state from the EFI variable (byte 4 == 1 means enabled)."""
    var = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    try:
        with open(var, "rb") as fh:
            data = fh.read()
        enabled = len(data) >= 5 and data[4] == 1
        return {"available": True, "enabled": enabled}
    except OSError:
        return {"available": False}


def collect_modules() -> dict:
    """Loaded kernel modules from /proc/modules (name -> only names kept)."""
    raw = _read("/proc/modules")
    if raw is None:
        return {"available": False}
    names = sorted(line.split()[0] for line in raw.splitlines() if line.strip())
    return {"available": True, "loaded": names, "count": len(names)}


def collect_dev_mem() -> dict:
    """Whether raw physical memory devices are openable (a cheating vector)."""
    present = [p for p in ("/dev/mem", "/dev/kmem", "/dev/port") if os.path.exists(p)]
    return {"available": True, "exposed": present}


def collect_ld_preload() -> dict:
    """Injected userspace libraries via the loader — classic cheat injection."""
    return {
        "available": True,
        "ld_preload": os.environ.get("LD_PRELOAD", ""),
        "ld_library_path": os.environ.get("LD_LIBRARY_PATH", ""),
    }


def collect_debugger() -> dict:
    """TracerPid in /proc/self/status: nonzero => a debugger is attached."""
    raw = _read("/proc/self/status")
    if raw is None:
        return {"available": False}
    for line in raw.splitlines():
        if line.startswith("TracerPid:"):
            pid = int(line.split()[1])
            return {"available": True, "tracer_pid": pid, "clean": pid == 0}
    return {"available": False}


def collect_kmod() -> dict:
    """Snapshot published by our kernel module at /proc/acheat/status, if loaded."""
    raw = _read("/proc/acheat/status")
    if raw is None:
        return {"available": False}
    return {"available": True, "raw": raw}


def collect_all(sim: dict | None = None) -> dict:
    """Gather every signal; overlay `sim` on top for off-target testing."""
    signals = {
        "taint": collect_taint(),
        "secure_boot": collect_secure_boot(),
        "modules": collect_modules(),
        "dev_mem": collect_dev_mem(),
        "ld_preload": collect_ld_preload(),
        "debugger": collect_debugger(),
        "kmod": collect_kmod(),
    }
    if sim:
        for key, value in sim.items():
            if isinstance(value, dict) and isinstance(signals.get(key), dict):
                signals[key] = {**signals[key], **value}
            else:
                signals[key] = value
    return signals


if __name__ == "__main__":
    import json

    print(json.dumps({"kernel": collect_kernel(), "signals": collect_all()}, indent=2))
