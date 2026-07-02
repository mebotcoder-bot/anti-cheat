#!/usr/bin/env python3
"""
Shared wire protocol between the anti-cheat client and server.

Design principle (the whole point of the system): the server never trusts a
value the client *claims*. The client must return a report that is (a) bound to
a fresh server-issued nonce (anti-replay) and (b) signed by a key the client
proved it holds at enrollment. On real hardware that key lives in the TPM and
the report carries a TPM quote over the boot PCRs, so a tampered OS cannot forge
a passing report without also forging hardware measurements.

Canonical serialization is used so the client and server sign/verify byte-for-byte
identical bytes.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding used as the signing input on both sides."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class Report:
    """Everything the client asserts about itself for one attestation round."""

    client_id: str
    nonce: str                       # echoed back so the server binds this round
    timestamp: float
    kernel: dict[str, Any]           # release string + parsed fields
    signals: dict[str, Any]          # integrity signals (taint, modules, ...)
    tpm: dict[str, Any] = field(default_factory=dict)  # quote/pcrs or {"mode":"software"}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def signing_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Report":
        return Report(
            client_id=d["client_id"],
            nonce=d["nonce"],
            timestamp=d["timestamp"],
            kernel=d["kernel"],
            signals=d["signals"],
            tpm=d.get("tpm", {}),
        )


@dataclass
class Verdict:
    verdict: str          # "PASS" | "FLAG" | "FAIL"
    score: int            # 0..100, higher = more trusted
    reasons: list[str]    # human-readable explanations

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
