#!/usr/bin/env python3
"""
Demo TPM PCR profiles.

A TPM measures the boot chain into Platform Configuration Registers (PCRs).
The server knows the digests a *good* image produces; a tampered boot (Secure
Boot off, shim replaced, unsigned kernel) changes them. Here we synthesize
deterministic PCR values for two boot states so both the client (which builds
the quote) and the server policy (which knows the good values) agree without
duplicating hex literals.

On real hardware these come from `tpm2_pcrread` on a reference machine.
"""
from __future__ import annotations

import hashlib


def _pcr(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


# PCRs 0/4/7 are the classic measured-boot set (firmware / bootloader / Secure Boot).
PROFILES: dict[str, dict[int, bytes]] = {
    "good": {
        0: _pcr("acheat:pcr0:firmware:v1"),
        4: _pcr("acheat:pcr4:shim+grub:signed"),
        7: _pcr("acheat:pcr7:secureboot=on"),
    },
    # A cheating box with Secure Boot disabled measures a different PCR 7.
    "bad_secureboot": {
        0: _pcr("acheat:pcr0:firmware:v1"),
        4: _pcr("acheat:pcr4:shim+grub:signed"),
        7: _pcr("acheat:pcr7:secureboot=off"),
    },
}

PCR_SELECT = [0, 4, 7]


def profile(name: str) -> dict[int, bytes]:
    return PROFILES[name]


def known_good_hex() -> dict[str, str]:
    """Server-side known-good policy as {index: sha256-hex}."""
    return {str(i): v.hex() for i, v in PROFILES["good"].items()}
