#!/usr/bin/env python3
"""
tools/hsm_demo.py — HealthPQC v2.0
HSM key lifecycle demo using SoftHSM2 (PKCS#11 interface).

Demonstrates the key management workflow for PQC migration planning.
Real HSMs (Thales Luna, Entrust nShield) use identical PKCS#11 API.

Prerequisites:
  macOS:  brew install softhsm
  Ubuntu: sudo apt install softhsm2 opensc

Initialize token first:
  softhsm2-util --init-token --slot 0 --label "QuantumBank-HSM" --pin 1234 --so-pin 5678

Run: python tools/hsm_demo.py
"""

import sys
import os

# PKCS#11 library paths by platform
PKCS11_PATHS = [
    "/usr/local/lib/softhsm/libsofthsm2.so",      # macOS Homebrew
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",   # macOS Homebrew ARM64
    "/usr/lib/softhsm/libsofthsm2.so",            # Ubuntu
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",  # Ubuntu alternative
]

TOKEN_LABEL = "QuantumBank-HSM"
USER_PIN = "1234"


def find_pkcs11_lib() -> str:
    """Find the SoftHSM2 PKCS#11 library on this system."""
    for path in PKCS11_PATHS:
        if os.path.exists(path):
            return path
    return None


def demo_with_pkcs11():
    """Full HSM demo using python-pkcs11 library."""
    try:
        import pkcs11
        from pkcs11 import KeyType, ObjectClass
    except ImportError:
        print("[ERROR] python-pkcs11 not installed.")
        print("        Run: pip install python-pkcs11")
        return False

    lib_path = find_pkcs11_lib()
    if not lib_path:
        print("[ERROR] SoftHSM2 library not found.")
        print("        Install: brew install softhsm  (macOS)")
        print("                 sudo apt install softhsm2  (Ubuntu)")
        return False

    print("=" * 60)
    print("HSM KEY LIFECYCLE DEMO — SoftHSM2 (PKCS#11)")
    print("=" * 60)
    print(f"Library:  {lib_path}")
    print(f"Token:    {TOKEN_LABEL}")
    print()

    try:
        lib = pkcs11.lib(lib_path)
        token = lib.get_token(token_label=TOKEN_LABEL)

        with token.open(user_pin=USER_PIN) as session:
            # List existing keys
            print("EXISTING KEYS IN HSM TOKEN:")
            print("-" * 60)
            key_count = 0
            for obj in session.get_objects({ObjectClass.PUBLIC_KEY}):
                print(f"  [PUBLIC]  {obj.label}")
                key_count += 1
            for obj in session.get_objects({ObjectClass.PRIVATE_KEY}):
                print(f"  [PRIVATE] {obj.label}")
                key_count += 1

            if key_count == 0:
                print("  (no keys found)")
            print()

            # Generate a new ECDSA key (simulating pre-migration state)
            print("GENERATING NEW KEY:")
            print("-" * 60)
            try:
                pub, priv = session.generate_keypair(
                    KeyType.EC,
                    256,  # P-256 curve
                    store=True,
                    label="healthpqc-demo-key",
                )
                print(f"  Created: {pub.label}")
                print(f"  Type:    ECDSA P-256 (classical — pre-migration)")
                print(f"  Status:  Stored in HSM token")
            except Exception as e:
                print(f"  Key generation skipped: {e}")
                print(f"  (key may already exist)")
            print()

            # PQC migration context
            print("PQC MIGRATION CONTEXT:")
            print("-" * 60)
            print("  Current:  ECDSA P-256 keys in HSM (Shor-vulnerable)")
            print("  Target:   ML-KEM-768 / ML-DSA-65 (FIPS 203/204)")
            print("  Blocker:  FIPS 140-3 HSM PQC validation pending")
            print("  Timeline: H2 2027 — first certified PQC HSM models")
            print()
            print("  Recommendation:")
            print("  • Phase 1-3: Migrate TLS/app layer (no HSM dependency)")
            print("  • Phase 4:   HSM root CA migration (after FIPS validation)")
            print("=" * 60)

        return True

    except pkcs11.PKCS11Error as e:
        print(f"[ERROR] PKCS#11 error: {e}")
        print()
        print("Token may not be initialized. Run:")
        print(f'  softhsm2-util --init-token --slot 0 --label "{TOKEN_LABEL}" --pin {USER_PIN} --so-pin 5678')
        return False


def demo_without_pkcs11():
    """Fallback demo without python-pkcs11 (shows CLI commands only)."""
    print("=" * 60)
    print("HSM KEY LIFECYCLE DEMO — CLI Reference")
    print("=" * 60)
    print()
    print("SoftHSM2 provides the same PKCS#11 interface as enterprise HSMs.")
    print("Below are the CLI commands to manage keys:")
    print()
    print("1. Initialize token:")
    print(f'   softhsm2-util --init-token --slot 0 --label "{TOKEN_LABEL}" \\')
    print(f'     --pin {USER_PIN} --so-pin 5678')
    print()
    print("2. List tokens:")
    print("   softhsm2-util --show-slots")
    print()
    print("3. Generate ECDSA key (via pkcs11-tool):")
    print("   pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \\")
    print(f"     --login --pin {USER_PIN} \\")
    print("     --keypairgen --key-type EC:prime256v1 \\")
    print('     --label "pre-migration-ecdsa-key"')
    print()
    print("4. List keys in token:")
    print("   pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \\")
    print(f"     --login --pin {USER_PIN} --list-objects")
    print()
    print("PQC MIGRATION NOTE:")
    print("-" * 60)
    print("Real HSMs (Thales Luna, Entrust nShield) use identical PKCS#11.")
    print("Only the --module path changes. PQC algorithm support requires")
    print("FIPS 140-3 validated firmware (expected H2 2027).")
    print("=" * 60)
    return True


def main():
    print()
    # Try full demo first, fall back to CLI reference
    if not demo_with_pkcs11():
        print()
        print("Falling back to CLI reference demo...")
        print()
        demo_without_pkcs11()


if __name__ == "__main__":
    main()
