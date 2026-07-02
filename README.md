# anti-cheat — a Linux anti-cheat foundation (EAC/BattlEye-style architecture)

A server-authoritative, hardware-rooted anti-cheat for Linux. Unlike a naive
"check the machine and trust it" tool, this treats the client as a **hostile
witness**: the client must return a *fresh, signed, hardware-bound* snapshot of
its integrity state, and the **server** makes the trust decision. A rooted
client can lie about individual values, but cannot forge a passing attestation
without also forging TPM measurements.

## Architecture

```
CLIENT (untrusted)                     SERVER (authority)
  kernel module  client/kmod/acheat.c    /enroll  register client pubkey (TOFU)
  daemon         client/agent.py         /nonce   fresh single-use challenge
   collectors    client/collectors.py    /attest  verify sig+nonce+PCRs, score
   attest/TPM    client/attest.py                 -> PASS / FLAG / FAIL
        │  signed report bound to nonce (+ TPM quote over boot PCRs)
        └────────────────────────────────►  verifier.py + policy.py
ROOT OF TRUST: TPM 2.0 + Secure Boot + measured boot (PCRs the OS can't forge)
```

## What it checks
- Kernel flavour is official + version >= policy minimum (reuses `anticheat.py`)
- Kernel taint flag (`/proc/sys/kernel/tainted`)
- Secure Boot enabled (EFI var)
- Banned/cheat kernel modules loaded
- Raw memory devices exposed (`/dev/mem`, `/dev/kmem`)
- `LD_PRELOAD` / injected libraries
- Debugger attached (`TracerPid`)
- Kernel-module snapshot from `/proc/acheat/status` (ring-0 signals)

## Security gates (verified in tests)
Any of these hard-fails before signals are even scored:
- **Signature** must verify against the enrolled public key
- **Nonce** must be fresh and single-use (anti-replay)
- **Enrollment** — unknown clients are rejected

## Run the demo (works off-target, e.g. macOS)
```
python3 test_e2e.py          # boots server, runs 2 clean + 1 tampered client
```
Or manually:
```
python3 server/server.py &                                  # start authority
python3 client/agent.py --sim scenarios/clean_ubuntu_1.json # -> PASS
python3 client/agent.py --sim scenarios/tampered.json       # -> FAIL
```

## Deploy on a real Linux target
1. Build + load the kernel module:
   `cd client/kmod && make && sudo insmod acheat.ko` (sign the `.ko` if Secure Boot is on)
2. Provision a TPM attestation key and enroll its public part with the server
   (`tpm2_createak`); `attest.py` auto-uses the TPM when `tpm2_quote`/`/dev/tpmrm0` exist.
3. Populate `server/policy.py` `KNOWN_GOOD_PCRS` from a reference image
   (`tpm2_pcrread`) and tune `MIN_KERNEL` / `BANNED_MODULES`.

## Honest limitations (what stands between this and EAC/BattlEye)
This is a **foundation**, not a finished commercial anti-cheat.
- Software-key fallback is for testing only; real trust needs the **TPM path**
  wired end-to-end (quote verification against known-good PCRs is currently a
  documented stub in `verifier.py`).
- The kernel module is a **reporter skeleton** — the hard detections (module-load
  kprobes, syscall-table/IDT integrity, `/dev/mem` notifiers, self-protection)
  are marked `TODO` in `acheat.c`.
- No anti-tamper/obfuscation on the client agent yet.
- On Linux, a determined attacker with hardware access is the real threat model;
  TPM + Secure Boot raises the bar but is not absolute.
```
```
