"""
verify_liboqs.py
Run this after completing docs/liboqs_install.md to confirm the library
is installed correctly and algorithms execute on your ARM64 hardware.

Usage:
    python verify_liboqs.py

Expected output:
    liboqs is fully operational. Ready for Phase 1.
"""

import oqs
import time
import sys


def check_availability():
    kems = oqs.get_enabled_KEMs()
    sigs = oqs.get_enabled_sigs()

    print("=== liboqs availability check ===")
    print(f"KEMs available: {len(kems)}")
    print(f"SIGs available: {len(sigs)}")

    required = {
        "KEM": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "SIG": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512", "Falcon-1024"]
    }

    all_present = True

    print()
    print("FIPS 203 (ML-KEM):")
    for alg in required["KEM"]:
        present = alg in kems
        status = "✓" if present else "✗ MISSING"
        print(f"  {alg:15s} {status}")
        if not present:
            all_present = False

    print()
    print("FIPS 204 (ML-DSA):")
    for alg in required["SIG"][:3]:
        present = alg in sigs
        status = "✓" if present else "✗ MISSING"
        print(f"  {alg:15s} {status}")
        if not present:
            all_present = False

    print()
    print("FIPS 206 (Falcon/FN-DSA):")
    for alg in required["SIG"][3:]:
        present = alg in sigs
        status = "✓" if present else "✗ MISSING"
        print(f"  {alg:15s} {status}")
        if not present:
            all_present = False

    return all_present


def test_kem():
    print()
    print("=== ML-KEM-768 key exchange test ===")
    with oqs.KeyEncapsulation("ML-KEM-768") as server:
        t0 = time.perf_counter()
        pub = server.generate_keypair()
        keygen_ms = (time.perf_counter() - t0) * 1000
        print(f"Public key generated: {len(pub)} bytes  ({keygen_ms:.3f} ms)")

        with oqs.KeyEncapsulation("ML-KEM-768") as client:
            t0 = time.perf_counter()
            ct, ss_client = client.encap_secret(pub)
            encap_ms = (time.perf_counter() - t0) * 1000
            print(f"Ciphertext:          {len(ct)} bytes  ({encap_ms:.3f} ms)")
            print(f"Shared secret:       {len(ss_client)} bytes")

        t0 = time.perf_counter()
        ss_server = server.decap_secret(ct)
        decap_ms = (time.perf_counter() - t0) * 1000
        print(f"Decapsulation:       {decap_ms:.3f} ms")

    if ss_client != ss_server:
        print("FAIL: Shared secrets do not match!")
        return False

    print("Shared secrets match: PASS")
    return True


def test_signature():
    print()
    print("=== Falcon-512 signature test (IoT use case) ===")
    message = b"SWERI-SWSLHD-clinical-device-authentication-v1"

    with oqs.Signature("Falcon-512") as signer:
        t0 = time.perf_counter()
        pub = signer.generate_keypair()
        keygen_ms = (time.perf_counter() - t0) * 1000
        print(f"Public key:      {len(pub)} bytes  ({keygen_ms:.1f} ms keygen)")

        t0 = time.perf_counter()
        sig = signer.sign(message)
        sign_ms = (time.perf_counter() - t0) * 1000
        print(f"Signature:       {len(sig)} bytes  ({sign_ms:.3f} ms sign)")
        print(f"Comparison:      ML-DSA-65 would be ~3309 bytes")
        print(f"IoT advantage:   {3309/len(sig):.1f}x smaller than ML-DSA-65")

    with oqs.Signature("Falcon-512") as verifier:
        t0 = time.perf_counter()
        valid = verifier.verify(message, sig, pub)
        verify_ms = (time.perf_counter() - t0) * 1000
        print(f"Verification:    {verify_ms:.3f} ms")

    if not valid:
        print("FAIL: Signature verification failed!")
        return False

    print("Signature verified: PASS")
    return True


def test_mldsa():
    print()
    print("=== ML-DSA-65 signature test (server use case) ===")
    message = b"clinical_code_signing_payload_v2.1.0"

    with oqs.Signature("ML-DSA-65") as signer:
        pub = signer.generate_keypair()
        sig = signer.sign(message)
        print(f"Public key: {len(pub)} bytes")
        print(f"Signature:  {len(sig)} bytes")

    with oqs.Signature("ML-DSA-65") as verifier:
        valid = verifier.verify(message, sig, pub)

    if not valid:
        print("FAIL: ML-DSA-65 verification failed!")
        return False

    print("ML-DSA-65 verified: PASS")
    return True


if __name__ == "__main__":
    print("HealthPQC — liboqs Verification Script")
    print("Platform: Apple Silicon ARM64")
    print("=" * 50)

    import platform
    arch = platform.machine()
    print(f"Architecture: {arch}")
    if arch != "arm64":
        print(f"WARNING: expected arm64, got {arch}")
        print("Results may not reflect native ARM64 performance")
    print()

    results = []
    results.append(check_availability())
    results.append(test_kem())
    results.append(test_signature())
    results.append(test_mldsa())

    print()
    print("=" * 50)
    if all(results):
        print("liboqs is fully operational on ARM64.")
        print("Ready for Phase 1: run `python benchmarks/healthcare_benchmark.py`")
        sys.exit(0)
    else:
        print("VERIFICATION FAILED — see errors above.")
        print("Check docs/liboqs_install.md troubleshooting section.")
        sys.exit(1)
