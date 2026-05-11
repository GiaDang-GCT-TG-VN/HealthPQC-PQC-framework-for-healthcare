#!/usr/bin/env python3
"""
verify_liboqs.py — HealthPQC v2.0
M6 FIX: checks minimum version (0.12+), validates required algorithms, runs smoke test.
Run before any benchmark: python verify_liboqs.py
"""

import sys
import time

MINIMUM_VERSION = (0, 12, 0)   # ML-KEM (FIPS 203) available from 0.12+
REQUIRED_KEMS   = ["ML-KEM-768", "ML-KEM-1024"]
REQUIRED_SIGS   = ["ML-DSA-65", "Falcon-512"]
OPTIONAL_KEMS   = ["ML-KEM-512", "Kyber768"]
OPTIONAL_SIGS   = ["ML-DSA-44", "ML-DSA-87", "SLH-DSA-SHA2-128s"]


def check() -> bool:
    failures = []

    # ------------------------------------------------------------------
    # 1. Import
    # ------------------------------------------------------------------
    try:
        import oqs
        print(f"[OK]   import oqs — liboqs-python installed")
    except ImportError as e:
        print(f"[FAIL] Cannot import oqs: {e}")
        print()
        print("  Fix:")
        print("    pip install liboqs-python")
        print("    (liboqs C library must also be installed)")
        print("    macOS:  brew install liboqs")
        print("    Ubuntu: sudo apt install liboqs-dev")
        print("    See:    docs/liboqs_install.md")
        return False

    # ------------------------------------------------------------------
    # 2. Version
    # ------------------------------------------------------------------
    version_str = getattr(oqs, "__version__", "0.0.0")
    try:
        parts = tuple(int(x) for x in version_str.split(".")[:3])
    except ValueError:
        parts = (0, 0, 0)

    if parts >= MINIMUM_VERSION:
        print(f"[OK]   liboqs version: {version_str}  (minimum: {'.'.join(str(x) for x in MINIMUM_VERSION)})")
    elif parts == (0, 0, 0):
        # Version not reported — check if ML-KEM is available instead
        test_kems = oqs.get_enabled_kem_mechanisms()
        if "ML-KEM-768" in test_kems:
            print(f"[OK]   liboqs version: {version_str} (unset) — ML-KEM available, assuming >= 0.12")
        else:
            print(f"[WARN] liboqs version unknown and ML-KEM not found — may be too old")
            failures.append("version")
    else:
        min_str = ".".join(str(x) for x in MINIMUM_VERSION)
        print(f"[FAIL] liboqs {version_str} too old — minimum required: {min_str}")
        print(f"       ML-KEM (FIPS 203) is not available in versions < {min_str}")
        print(f"       ML-KEM was called 'Kyber' in older versions — algorithm names differ")
        failures.append("version")

    # ------------------------------------------------------------------
    # 3. Required algorithms
    # ------------------------------------------------------------------
    available_kems = set(oqs.get_enabled_kem_mechanisms())
    available_sigs = set(oqs.get_enabled_sig_mechanisms())

    for algo in REQUIRED_KEMS:
        if algo in available_kems:
            print(f"[OK]   KEM required:  {algo}")
        else:
            print(f"[FAIL] KEM missing:   {algo}  ← required for HealthPQC benchmarks")
            failures.append(f"missing-{algo}")

    for algo in REQUIRED_SIGS:
        if algo in available_sigs:
            print(f"[OK]   SIG required:  {algo}")
        else:
            print(f"[FAIL] SIG missing:   {algo}  ← required for HealthPQC benchmarks")
            failures.append(f"missing-{algo}")

    for algo in OPTIONAL_KEMS:
        tag = "[OK]  " if algo in available_kems else "[INFO]"
        print(f"{tag}  KEM optional: {algo}  {'✓' if algo in available_kems else '(not available)'}")

    for algo in OPTIONAL_SIGS:
        tag = "[OK]  " if algo in available_sigs else "[INFO]"
        print(f"{tag}  SIG optional: {algo}  {'✓' if algo in available_sigs else '(not available)'}")

    # ------------------------------------------------------------------
    # 4. Smoke test — actually run ML-KEM-768
    # ------------------------------------------------------------------
    if "ML-KEM-768" in available_kems:
        try:
            t0 = time.time()
            with oqs.KeyEncapsulation("ML-KEM-768") as kem:
                pub = kem.generate_keypair()
                ct, ss = kem.encap_secret(pub)
                dec = kem.decap_secret(ct)
            elapsed_ms = (time.time() - t0) * 1000

            if dec == ss:
                print(f"[OK]   ML-KEM-768 smoke test passed  "
                      f"(keygen+encap+decap in {elapsed_ms:.1f}ms | pubkey={len(pub)}B ct={len(ct)}B)")
            else:
                print(f"[FAIL] ML-KEM-768 decapsulation mismatch — shared secrets differ")
                failures.append("kem-smoke-test")

        except Exception as e:
            print(f"[FAIL] ML-KEM-768 smoke test exception: {e}")
            failures.append("kem-smoke-test")
    else:
        print(f"[SKIP] ML-KEM-768 smoke test — algorithm not available")

    # 5. Smoke test — ML-DSA-65
    if "ML-DSA-65" in available_sigs:
        try:
            with oqs.Signature("ML-DSA-65") as signer:
                pub = signer.generate_keypair()
                sig = signer.sign(b"HealthPQC smoke test")
                ok  = signer.verify(b"HealthPQC smoke test", sig, pub)
            if ok:
                print(f"[OK]   ML-DSA-65 smoke test passed   (sig={len(sig)}B pubkey={len(pub)}B)")
            else:
                print(f"[FAIL] ML-DSA-65 verify returned False")
                failures.append("sig-smoke-test")
        except Exception as e:
            print(f"[FAIL] ML-DSA-65 smoke test exception: {e}")
            failures.append("sig-smoke-test")
    else:
        print(f"[SKIP] ML-DSA-65 smoke test — algorithm not available")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print()
    if not failures:
        print("✓  All checks passed — HealthPQC benchmarks ready to run.")
        print()
        print("  Quick start:")
        print("    python benchmarks/healthcare_benchmark.py")
        print("    python tools/cbom_scanner.py --target .")
        print("    python tools/pqc_pki_demo.py")
    else:
        print(f"✗  {len(failures)} check(s) failed: {failures}")
        print("  Fix the errors above before running benchmarks.")

    return len(failures) == 0


if __name__ == "__main__":
    ok = check()
    sys.exit(0 if ok else 1)
