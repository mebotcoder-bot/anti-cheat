#!/usr/bin/env python3
"""
Adversarial tests: prove the cryptographic gates reject a lying/MITM client.

Each case must be REJECTED:
  1. certificate not issued by the server CA (rogue CA)
  2. forged/mutated TPM quote (signature no longer valid)
  3. replayed nonce
  4. tampered server verdict (client detects the bad signature)

Run: python3 test_security.py
"""
from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

os.environ.setdefault("ACHEAT_STATE", "state")
from server import server as srv
from crypto import keys, pcrs, pki
from crypto.softtpm import SoftTPM
from protocol import Report, canonical_bytes

HOST, PORT = "127.0.0.1", 8811
BASE = f"http://{HOST}:{PORT}"


def post(path, obj):
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req).read())


def sign(key, data):
    return base64.b64encode(key.sign(data, ec.ECDSA(hashes.SHA256()))).decode()


def report(cid, nonce, key, profile="good", kernel=None, signals=None):
    return Report(cid, nonce, time.time(),
                  kernel or {"flavour": "generic", "flavour_official": True,
                             "base_version": "6.8.0", "abi": 45},
                  signals or {}, SoftTPM(key, pcrs.profile(profile)).quote(nonce, pcrs.PCR_SELECT))


def verdict_of(res):
    return res["verdict_obj"]["verdict"]


def main() -> int:
    httpd = ThreadingHTTPServer((HOST, PORT), srv.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)

    k = keys.generate()
    e = post("/enroll", {"client_id": "eve", "csr_pem": pki.csr_to_pem(pki.make_csr(k, "eve"))})
    cert_pem, ca_pem = e["cert_pem"], e["ca_pem"]

    fails = 0

    # 1. rogue CA
    rogue = keys.generate()
    rogue_cert = pki.create_ca("rogue", rogue)
    fake = pki.cert_to_pem(pki.issue_cert(rogue, rogue_cert, pki.make_csr(k, "eve")))
    n = post("/nonce", {"client_id": "eve"})["nonce"]
    r = report("eve", n, k)
    res = post("/attest", {"report": r.to_dict(), "signature": sign(k, r.signing_bytes()), "cert_pem": fake})
    ok = verdict_of(res) == "FAIL"
    print(f"1) rogue CA cert    -> {verdict_of(res)}  [{'OK' if ok else 'LEAK'}]")
    fails += not ok

    # 2. forged quote
    n = post("/nonce", {"client_id": "eve"})["nonce"]
    r = report("eve", n, k)
    q = r.tpm
    b = bytearray(bytes.fromhex(q["attest"])); b[-1] ^= 0xFF; q["attest"] = b.hex()
    res = post("/attest", {"report": r.to_dict(), "signature": sign(k, r.signing_bytes()), "cert_pem": cert_pem})
    ok = verdict_of(res) == "FAIL"
    print(f"2) forged TPM quote -> {verdict_of(res)}  [{'OK' if ok else 'LEAK'}]")
    fails += not ok

    # 3. replay
    n = post("/nonce", {"client_id": "eve"})["nonce"]
    r = report("eve", n, k)
    s = sign(k, r.signing_bytes())
    post("/attest", {"report": r.to_dict(), "signature": s, "cert_pem": cert_pem})
    res = post("/attest", {"report": r.to_dict(), "signature": s, "cert_pem": cert_pem})
    ok = verdict_of(res) == "FAIL"
    print(f"3) replayed nonce   -> {verdict_of(res)}  [{'OK' if ok else 'LEAK'}]")
    fails += not ok

    # 4. tampered verdict (start from a genuine FAIL, forge to PASS)
    n = post("/nonce", {"client_id": "eve"})["nonce"]
    r = report("eve", n, k, profile="bad_secureboot",
               kernel={"flavour": "cheat", "flavour_official": False},
               signals={"secure_boot": {"available": True, "enabled": False}})
    res = post("/attest", {"report": r.to_dict(), "signature": sign(k, r.signing_bytes()), "cert_pem": cert_pem})
    ca = pki.cert_from_pem(ca_pem)
    forged = dict(res["verdict_obj"]); forged["verdict"] = "PASS"; forged["score"] = 100
    try:
        ca.public_key().verify(base64.b64decode(res["verdict_sig"]),
                               canonical_bytes(forged), ec.ECDSA(hashes.SHA256()))
        accepted = True
    except Exception:  # noqa: BLE001
        accepted = False
    ok = not accepted
    print(f"4) tampered verdict -> {'REJECTED' if not accepted else 'ACCEPTED'}  [{'OK' if ok else 'LEAK'}]")
    fails += not ok

    httpd.shutdown()
    print("=" * 50)
    print("[security] ALL GATES HOLD" if fails == 0 else f"[security] {fails} LEAK(S)")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
