#!/usr/bin/env python3
"""
End-to-end test: boot the attestation server, then run three simulated clients
(two clean Ubuntu boxes, one cheating box) through the full
enroll -> nonce -> sign -> verify pipeline. Asserts the server's verdicts.

Run: python3 test_e2e.py
"""
from __future__ import annotations

import json
import os
import threading
import time

from http.server import ThreadingHTTPServer

from server import server as srv
from client import agent

HOST, PORT = "127.0.0.1", 8799
BASE = f"http://{HOST}:{PORT}"
HERE = os.path.dirname(os.path.abspath(__file__))


def start_server() -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((HOST, PORT), srv.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return httpd


def run_client(scenario: str, client_id: str) -> int:
    # Each client gets its own per-client key/cert (default paths keyed by id).
    with open(os.path.join(HERE, "scenarios", scenario), encoding="utf-8") as fh:
        sim = json.load(fh)
    return agent.run(BASE, client_id, sim)


def main() -> int:
    httpd = start_server()
    print(f"[test] server up on {BASE}\n")

    cases = [
        ("clean_ubuntu_1.json", "gamer-alice", "PASS"),
        ("clean_ubuntu_2.json", "gamer-bob", "PASS"),
        ("tampered.json", "cheater-eve", "FAIL"),
    ]

    failures = 0
    for scenario, cid, expected in cases:
        print(f"###### {scenario}  (expect {expected}) ######")
        rc = run_client(scenario, cid)
        got = "PASS" if rc == 0 else "FAIL/FLAG"
        ok = (expected == "PASS" and rc == 0) or (expected == "FAIL" and rc != 0)
        print(f"[test] {'OK' if ok else 'MISMATCH'} exit={rc} expected~={expected}\n")
        failures += 0 if ok else 1

    httpd.shutdown()
    print("=" * 60)
    print(f"[test] {'ALL PASSED' if failures == 0 else f'{failures} FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
