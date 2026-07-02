#!/usr/bin/env python3
"""
Anti-cheat attestation server — the trust authority.

Endpoints (JSON POST):
  /enroll  {client_id, pubkey_pem}      -> {ok}          (TOFU registration)
  /nonce   {client_id}                  -> {nonce, ttl}  (fresh, single-use)
  /attest  {report, signature}          -> Verdict       (verify + score)

State is in-memory (enrollments + outstanding nonces). Swap for a real datastore
in production. Nonces are single-use and time-limited to stop replay of a good
report captured earlier.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server import verifier  # noqa: E402

NONCE_TTL = 30  # seconds

_ENROLLED: dict[str, str] = {}          # client_id -> public key PEM (TOFU)
_NONCES: dict[str, tuple[str, float]] = {}  # nonce -> (client_id, issued_at)


def _issue_nonce(client_id: str) -> str:
    nonce = secrets.token_hex(16)
    _NONCES[nonce] = (client_id, time.time())
    return nonce


def _consume_nonce(nonce: str, client_id: str) -> bool:
    """Single-use + fresh + bound to the same client. Pops on use."""
    entry = _NONCES.pop(nonce, None)
    if entry is None:
        return False
    owner, issued = entry
    return owner == client_id and (time.time() - issued) <= NONCE_TTL


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quieter test output
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
                cid, pem = payload["client_id"], payload["pubkey_pem"]
                # TOFU: first key wins; a changed key on an existing client is refused.
                if cid in _ENROLLED and _ENROLLED[cid] != pem:
                    return self._send({"ok": False, "error": "key change refused"}, 409)
                _ENROLLED.setdefault(cid, pem)
                return self._send({"ok": True})

            if self.path == "/nonce":
                cid = payload["client_id"]
                return self._send({"nonce": _issue_nonce(cid), "ttl": NONCE_TTL})

            if self.path == "/attest":
                report = payload["report"]
                signature = payload["signature"]
                cid = report["client_id"]
                nonce_ok = _consume_nonce(report.get("nonce", ""), cid)
                result = verifier.verify(
                    report, signature, _ENROLLED.get(cid), nonce_ok
                )
                return self._send(result.to_dict())

            self._send({"error": "unknown endpoint"}, 404)
        except Exception as exc:  # noqa: BLE001
            self._send({"error": str(exc)}, 400)


def serve(host: str = "127.0.0.1", port: int = 8787):
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"anti-cheat server listening on http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    args = p.parse_args()
    serve(args.host, args.port)
