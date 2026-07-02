#!/usr/bin/env python3
"""
Anti-cheat attestation server — the trust authority + certificate authority.

Endpoints (JSON POST):
  /enroll  {client_id, csr_pem}        -> {cert_pem, ca_pem}   (CA issues client cert)
  /nonce   {client_id}                 -> {nonce, ttl}         (fresh, single-use)
  /attest  {report, signature, cert_pem} -> {verdict_obj, verdict_sig}

The server holds a CA (root key + cert). Clients enroll by CSR and receive a
cert chained to that CA. Attestations are verified against the cert; the server
signs its verdict with the CA key so clients can authenticate the response.
State (CA, nonces) is in-memory/on-disk for the demo; use a real datastore and
an HSM-protected CA key in production.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol import Verdict, canonical_bytes  # noqa: E402
from server import verifier  # noqa: E402
from crypto import keys, pki  # noqa: E402

NONCE_TTL = 30  # seconds
_STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state")

_NONCES: dict[str, tuple[str, float]] = {}


class CA:
    """Server certificate authority + verdict signer."""

    def __init__(self):
        base = os.environ.get("ACHEAT_STATE", _STATE)
        key_path = os.path.join(base, "ca.key.pem")
        cert_path = os.path.join(base, "ca.cert.pem")
        self.key = keys.load_or_create(key_path)
        if os.path.exists(cert_path):
            with open(cert_path, encoding="ascii") as fh:
                self.cert = pki.cert_from_pem(fh.read())
        else:
            self.cert = pki.create_ca("acheat-root-CA", self.key)
            with open(cert_path, "w", encoding="ascii") as fh:
                fh.write(pki.cert_to_pem(self.cert))

    def issue(self, csr_pem: str) -> str:
        csr = pki.csr_from_pem(csr_pem)
        return pki.cert_to_pem(pki.issue_cert(self.key, self.cert, csr))

    def ca_pem(self) -> str:
        return pki.cert_to_pem(self.cert)

    def sign_verdict(self, verdict: Verdict) -> dict:
        obj = verdict.to_dict()
        sig = self.key.sign(canonical_bytes(obj), ec.ECDSA(hashes.SHA256()))
        return {"verdict_obj": obj, "verdict_sig": base64.b64encode(sig).decode("ascii")}


_CA: CA | None = None


def _ca() -> CA:
    global _CA
    if _CA is None:
        _CA = CA()
    return _CA


def _issue_nonce(client_id: str) -> str:
    nonce = secrets.token_hex(16)
    _NONCES[nonce] = (client_id, time.time())
    return nonce


def _consume_nonce(nonce: str, client_id: str) -> bool:
    entry = _NONCES.pop(nonce, None)
    if entry is None:
        return False
    owner, issued = entry
    return owner == client_id and (time.time() - issued) <= NONCE_TTL


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

    def _send(self, obj: dict, code: int = 200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        try:
            payload = self._read_json()
            if self.path == "/enroll":
                cert_pem = _ca().issue(payload["csr_pem"])
                return self._send({"cert_pem": cert_pem, "ca_pem": _ca().ca_pem()})

            if self.path == "/nonce":
                cid = payload["client_id"]
                return self._send({"nonce": _issue_nonce(cid), "ttl": NONCE_TTL})

            if self.path == "/attest":
                report = payload["report"]
                cid = report["client_id"]
                nonce_ok = _consume_nonce(report.get("nonce", ""), cid)
                verdict = verifier.verify(
                    report, payload["signature"], payload.get("cert_pem"),
                    _ca().cert, nonce_ok,
                )
                return self._send(_ca().sign_verdict(verdict))

            self._send({"error": "unknown endpoint"}, 404)
        except Exception as exc:  # noqa: BLE001
            self._send({"error": str(exc)}, 400)


def serve(host: str = "127.0.0.1", port: int = 8787):
    _ca()  # initialize CA up front
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"anti-cheat server (CA + attestation) on http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    args = p.parse_args()
    serve(args.host, args.port)
