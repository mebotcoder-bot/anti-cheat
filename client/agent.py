#!/usr/bin/env python3
"""
Anti-cheat client agent (userspace daemon).

One attestation round:
  1. enroll (first run): register this client's public key with the server.
  2. request a fresh nonce from the server.
  3. collect kernel + integrity signals (+ TPM quote bound to the nonce).
  4. build a Report, sign it, POST it to /attest.
  5. print the server's verdict; exit 0 (PASS) / 1 (FLAG/FAIL).

The client deliberately does NOT decide pass/fail itself — the server does. The
client's job is only to produce a fresh, signed, hardware-bound snapshot.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol import Report, canonical_bytes  # noqa: E402
from client import collectors  # noqa: E402
from client.attest import Identity  # noqa: E402


def _post(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run(server: str, client_id: str, sim: dict | None) -> int:
    ident = Identity(client_id)
    sim = sim or {}

    # 1. Enroll: send a CSR, receive an X.509 client cert + the CA cert.
    enroll = _post(f"{server}/enroll", {"client_id": client_id, "csr_pem": ident.csr_pem()})
    ident.store_cert(enroll["cert_pem"], enroll["ca_pem"])

    # 2. Fresh nonce.
    nonce = _post(f"{server}/nonce", {"client_id": client_id})["nonce"]

    # 3. Collect signals + a TPM quote over the boot PCRs bound to the nonce.
    #    A scenario file may overlay kernel/signals and pick a PCR profile so
    #    real Ubuntu boot states can be simulated off-target.
    kernel = collectors.collect_kernel()
    kernel.update(sim.get("kernel", {}))
    pcr_profile = sim.get("tpm", {}).get("pcr_profile", "good")
    report = Report(
        client_id=client_id,
        nonce=nonce,
        timestamp=time.time(),
        kernel=kernel,
        signals=collectors.collect_all(sim=sim.get("signals")),
        tpm=ident.quote(nonce, pcr_profile),
    )

    # 4. Sign the canonical report; submit report + cert.
    signature = base64.b64encode(ident.sign(report.signing_bytes())).decode("ascii")
    result = _post(f"{server}/attest", {
        "report": report.to_dict(),
        "signature": signature,
        "cert_pem": ident.cert_pem,
    })

    # 5. Authenticate the server's signed verdict, then report it.
    verdict_obj = result["verdict_obj"]
    verdict_sig = base64.b64decode(result["verdict_sig"])
    if not ident.verify_server_sig(canonical_bytes(verdict_obj), verdict_sig):
        print("\033[31m[SECURITY] server verdict signature INVALID — discarding\033[0m")
        return 2
    verdict = verdict_obj["verdict"]
    color = {"PASS": "\033[32m", "FLAG": "\033[33m", "FAIL": "\033[31m"}.get(verdict, "")
    print("=" * 60)
    print(f" client   : {client_id}   (attestation: {ident.mode}, cert-verified)")
    print(f" kernel   : {report.kernel.get('release')}")
    print(f" verdict  : {color}{verdict}\033[0m   score={verdict_obj['score']}/100  (server-signed)")
    for reason in verdict_obj["reasons"]:
        print(f"    - {reason}")
    print("=" * 60)
    return 0 if verdict == "PASS" else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="anti-cheat client agent")
    p.add_argument("--server", default="http://127.0.0.1:8787")
    p.add_argument("--client-id", default=os.uname().nodename if hasattr(os, "uname") else "client")
    p.add_argument("--sim", help="path to a JSON signal-overlay file (testing only)")
    p.add_argument("--key", help="override agent key path (testing: isolate identities)")
    args = p.parse_args(argv)

    if args.key:
        os.environ["ACHEAT_KEY_PATH"] = args.key

    sim = None
    if args.sim:
        with open(args.sim, "r", encoding="utf-8") as fh:
            sim = json.load(fh)

    return run(args.server, args.client_id, sim)


if __name__ == "__main__":
    raise SystemExit(main())
