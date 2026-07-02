# anti-cheat — a Linux anti-cheat foundation (EAC/BattlEye-style architecture)

A server-authoritative, hardware-rooted anti-cheat for Linux. It treats the
client as a **hostile witness**: the client must return a *fresh, signed,
hardware-attested* snapshot of its integrity state, and the **server** makes the
trust decision. A rooted client can lie about a value, but cannot forge a passing
attestation without also forging TPM measurements and a CA-issued certificate.

## Cryptography (real, not a toy)
- **PKI enrollment** — the server runs an X.509 CA; clients enroll by CSR and get
  a client certificate. Every attestation is verified against the cert chain
  (`crypto/pki.py`). Keys are EC P-256, PKCS#8, optionally passphrase-encrypted
  at rest (`crypto/keys.py`).
- **TPM 2.0 quote attestation** — the client returns a quote in TPM wire format
  (`TPMS_ATTEST`: magic / type / nonce as qualifying data / PCR digest) signed by
  its key; the server verifies signature, freshness, digest binding, and PCR
  values against a known-good boot policy (`crypto/tpm_verify.py`). A software TPM
  (`crypto/softtpm.py`) emits genuine-format quotes so the real verifier path runs
  off-target; a hardware TPM backs the same interface in production.
- **Signed verdicts** — the server signs its decision with the CA key so a MITM
  cannot forge a PASS; the client verifies it (`client/attest.py`).

## Architecture
```
CLIENT (untrusted)                     SERVER (authority + CA)
  kernel module  client/kmod/acheat.c    /enroll  CSR -> X.509 client cert
  daemon         client/agent.py         /nonce   fresh single-use challenge
   collectors    client/collectors.py    /attest  verify cert+sig+nonce+quote,
   identity+TPM  client/attest.py                  score signals -> signed verdict
        │  signed report + cert + TPM quote (bound to nonce, over boot PCRs)
        └───────────────────►  server/verifier.py + server/policy.py
ROOT OF TRUST: TPM 2.0 + Secure Boot + measured boot (PCRs the OS can't forge)
```

## Integrity signals scored
Kernel flavour/version (`anticheat.py`), kernel taint, Secure Boot state, banned
cheat modules, `/dev/mem` exposure, `LD_PRELOAD` injection, attached debugger,
and the ring-0 snapshot from `/proc/acheat/status`.

## Hard gates (proved in test_security.py)
Rejected before any signal is scored: cert not chained to the CA, invalid/forged
TPM quote, stale/replayed nonce, wrong cert CN, bad report signature — and the
client rejects any verdict whose server signature doesn't verify.

## Run it (works off-target, e.g. macOS)
```
python3 test_e2e.py        # 2 clean Ubuntu clients PASS (100/100), 1 tampered FAILs
python3 test_security.py   # all adversarial gates hold
```
Manual:
```
python3 server/server.py &
python3 client/agent.py --sim scenarios/clean_ubuntu_1.json   # -> PASS
python3 client/agent.py --sim scenarios/tampered.json         # -> FAIL
```

## Deploy on a real Linux target
1. `cd client/kmod && make && sudo insmod acheat.ko` (sign the `.ko` under Secure Boot).
2. Provision a TPM AK (`tpm2_createak`); `attest.py` uses the hardware TPM when
   `tpm2_quote` + `/dev/tpmrm0` are present.
3. Populate `server/policy.py` known-good PCRs from a reference image
   (`tpm2_pcrread`) and tune `MIN_KERNEL` / `BANNED_MODULES`.
4. Protect the CA key in an HSM; put the server behind TLS.

## Honest limitations (what still stands between this and EAC/BattlEye)
This is a strong **foundation** with real crypto, not a finished commercial
anti-cheat.
- The kernel module is a **reporter skeleton** — the hard ring-0 detections
  (module-load kprobes, syscall-table/IDT integrity, `/dev/mem` notifiers, self-
  protection) are marked `TODO` in `acheat.c`.
- No client-side anti-tamper/obfuscation yet (a real product hardens the agent
  against being patched or unloaded).
- The software TPM is for testing; production trust requires a real TPM 2.0 and
  full `TPMS_ATTEST` parsing (e.g. via tpm2-pytss) plus EK/credential activation.
- On Linux, an attacker with physical/hardware access remains the hard case;
  TPM + Secure Boot raises the bar substantially but is not absolute.
```
```
