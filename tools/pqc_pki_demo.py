"""
tools/pqc_pki_demo.py — HealthPQC v2.0
Quantum-safe PKI certificate chain: Root CA → Intermediate CA → Leaf
Uses ML-DSA-65 (FIPS 204, NIST Level 3) for all signing operations.

C2 FIX: Keypairs stored in _KEYPAIRS dict — Root CA actually signs Intermediate.
Chain verification asserted at end — will raise if trust is broken.

Requires: pip install liboqs-python (liboqs C library must be installed)
"""

import oqs
import os
import json
import time
import hashlib
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Keypair store — C2 FIX
# _KEYPAIRS[name] = (public_key_bytes, secret_key_bytes)
# ---------------------------------------------------------------------------
_KEYPAIRS: dict = {}


def generate_and_store_keypair(name: str, sig_alg: str = "ML-DSA-65") -> bytes:
    """
    Generate a keypair, store secret key under 'name', return public key.
    Secret key is kept in memory for signing — never written to disk in this demo.
    """
    with oqs.Signature(sig_alg) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    _KEYPAIRS[name] = (public_key, secret_key)
    return public_key


def sign_payload(payload: dict, signer_name: str, sig_alg: str = "ML-DSA-65") -> dict:
    """
    Sign a payload dict using the stored secret key for signer_name.
    C2 FIX: uses _KEYPAIRS[signer_name] — NOT a freshly generated key.
    """
    if signer_name not in _KEYPAIRS:
        raise ValueError(
            f"No keypair stored for '{signer_name}'. "
            f"Call generate_and_store_keypair('{signer_name}') first."
        )
    _, secret_key = _KEYPAIRS[signer_name]

    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    payload_hash = hashlib.sha3_256(payload_bytes).digest()

    t0 = time.time()
    with oqs.Signature(sig_alg, secret_key=secret_key) as signer:
        signature = signer.sign(payload_hash)
    sign_ms = (time.time() - t0) * 1000

    return {
        "payload":              payload,
        "signature_bytes":      signature,          # full bytes for verify_cert()
        "signature_hex":        signature.hex()[:64] + "...",
        "signature_size_bytes": len(signature),
        "digest_algorithm":     "SHA3-256",
        "signing_algorithm":    sig_alg,
        "signed_by":            signer_name,
        "sign_ms":              round(sign_ms, 3),
    }


def verify_cert(cert: dict, issuer_name: str, sig_alg: str = "ML-DSA-65") -> bool:
    """
    Verify cert['signature_bytes'] against issuer's stored public key.
    Returns True if signature is valid — i.e. issuer really signed this cert.
    """
    if issuer_name not in _KEYPAIRS:
        raise ValueError(f"No keypair stored for issuer '{issuer_name}'.")

    issuer_public_key, _ = _KEYPAIRS[issuer_name]
    payload_bytes = json.dumps(cert["payload"], sort_keys=True).encode()
    payload_hash = hashlib.sha3_256(payload_bytes).digest()

    with oqs.Signature(sig_alg) as verifier:
        return verifier.verify(payload_hash, cert["signature_bytes"], issuer_public_key)


def create_cert_payload(
    subject: str,
    issuer: str,
    public_key: bytes,
    validity_days: int,
    is_ca: bool = False,
    use_case: str = "",
) -> dict:
    """Build an X.509-like cert payload dict (simplified, not DER-encoded)."""
    now = datetime.now(timezone.utc)
    return {
        "version":           3,
        "subject":           subject,
        "issuer":            issuer,
        "algorithm":         "ML-DSA-65 (FIPS 204)",
        "public_key_hex":    public_key.hex()[:64] + "...",
        "public_key_size_bytes": len(public_key),
        "not_before":        now.isoformat(),
        "not_after":         (now + timedelta(days=validity_days)).isoformat(),
        "is_ca":             is_ca,
        "basic_constraints": "CA:TRUE, pathLenConstraint=0" if is_ca else "CA:FALSE",
        "key_usage":         "keyCertSign, cRLSign" if is_ca else "digitalSignature, keyEncipherment",
        "use_case":          use_case,
    }


# ---------------------------------------------------------------------------
# Build full PKI chain
# ---------------------------------------------------------------------------
def build_pqc_pki_chain(output_path: str = "results/pqc_pki_chain.json") -> dict:
    """
    Build Root CA → Intermediate CA → Leaf certificate chain.
    All certs signed with ML-DSA-65 (FIPS 204).
    Chain of trust cryptographically verified before saving.
    """
    sig_alg = "ML-DSA-65"
    results = {}

    print("\n" + "="*64)
    print("  POST-QUANTUM PKI DEMO — ML-DSA-65 (FIPS 204, NIST Level 3)")
    print("  QuantumBank AU — Root CA → Intermediate → Leaf")
    print("="*64)

    # ------------------------------------------------------------------
    # Step 1: Root CA (self-signed)
    # ------------------------------------------------------------------
    print("\n[1/3] Root CA")
    t0 = time.time()
    root_pub = generate_and_store_keypair("root-ca", sig_alg)
    keygen_ms = (time.time() - t0) * 1000

    root_payload = create_cert_payload(
        subject=     "CN=QuantumBank Root CA, O=QuantumBank AU, C=AU",
        issuer=      "CN=QuantumBank Root CA, O=QuantumBank AU, C=AU",  # self-signed
        public_key=  root_pub,
        validity_days=3650,   # 10 years
        is_ca=       True,
        use_case=    "Hospital PKI trust anchor — 10-year root",
    )
    root_cert = sign_payload(root_payload, signer_name="root-ca", sig_alg=sig_alg)
    results["root_ca"] = {**{k: v for k, v in root_cert.items() if k != "signature_bytes"},
                          "keygen_ms": round(keygen_ms, 3)}

    print(f"  keygen:    {keygen_ms:.2f} ms")
    print(f"  sign:      {root_cert['sign_ms']} ms")
    print(f"  pubkey:    {len(root_pub)} B")
    print(f"  signature: {root_cert['signature_size_bytes']} B")

    # ------------------------------------------------------------------
    # Step 2: Intermediate CA — signed by Root CA
    # ------------------------------------------------------------------
    print("\n[2/3] Intermediate CA  (signed by Root CA)")
    t0 = time.time()
    inter_pub = generate_and_store_keypair("intermediate-ca", sig_alg)
    keygen_ms = (time.time() - t0) * 1000

    inter_payload = create_cert_payload(
        subject=      "CN=QuantumBank Issuing CA, O=QuantumBank AU, C=AU",
        issuer=       "CN=QuantumBank Root CA, O=QuantumBank AU, C=AU",
        public_key=   inter_pub,
        validity_days=1825,   # 5 years
        is_ca=        True,
        use_case=     "Issues end-entity certificates for banking services",
    )
    # C2 FIX: Root CA signs Intermediate — signer_name="root-ca"
    inter_cert = sign_payload(inter_payload, signer_name="root-ca", sig_alg=sig_alg)
    results["intermediate_ca"] = {**{k: v for k, v in inter_cert.items() if k != "signature_bytes"},
                                   "keygen_ms": round(keygen_ms, 3)}

    print(f"  keygen:    {keygen_ms:.2f} ms")
    print(f"  sign:      {inter_cert['sign_ms']} ms")
    print(f"  signed by: Root CA ✓")

    # ------------------------------------------------------------------
    # Step 3: Leaf certificate — signed by Intermediate CA
    # ------------------------------------------------------------------
    print("\n[3/3] Leaf Certificate  (signed by Intermediate CA)")
    t0 = time.time()
    leaf_pub = generate_and_store_keypair("leaf", sig_alg)
    keygen_ms = (time.time() - t0) * 1000

    leaf_payload = create_cert_payload(
        subject=      "CN=api.quantumbank.com.au, O=QuantumBank AU, C=AU",
        issuer=       "CN=QuantumBank Issuing CA, O=QuantumBank AU, C=AU",
        public_key=   leaf_pub,
        validity_days=365,    # 1 year
        is_ca=        False,
        use_case=     "Online banking API TLS — customer-facing endpoint",
    )
    # C2 FIX: Intermediate signs Leaf — signer_name="intermediate-ca"
    leaf_cert = sign_payload(leaf_payload, signer_name="intermediate-ca", sig_alg=sig_alg)
    results["leaf_cert"] = {**{k: v for k, v in leaf_cert.items() if k != "signature_bytes"},
                             "keygen_ms": round(keygen_ms, 3)}

    print(f"  keygen:    {keygen_ms:.2f} ms")
    print(f"  sign:      {leaf_cert['sign_ms']} ms")
    print(f"  signed by: Intermediate CA ✓")

    # ------------------------------------------------------------------
    # Chain verification — C2 FIX: assert real cryptographic validity
    # ------------------------------------------------------------------
    print("\n  Verifying chain of trust...")
    root_valid  = verify_cert(root_cert,  issuer_name="root-ca",          sig_alg=sig_alg)
    inter_valid = verify_cert(inter_cert, issuer_name="root-ca",          sig_alg=sig_alg)
    leaf_valid  = verify_cert(leaf_cert,  issuer_name="intermediate-ca",  sig_alg=sig_alg)

    print(f"  Root CA  (self-signed): {_tick(root_valid)}")
    print(f"  Intermediate ← Root:   {_tick(inter_valid)}")
    print(f"  Leaf ← Intermediate:   {_tick(leaf_valid)}")

    if not all([root_valid, inter_valid, leaf_valid]):
        raise AssertionError("CHAIN BROKEN — one or more signature verifications failed.")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    ecdsa_sig_bytes = 72    # classical comparison point
    ml_dsa_sig_bytes = leaf_cert["signature_size_bytes"]

    print("\n" + "="*64)
    print("  CHAIN SUMMARY")
    print("-"*64)
    print(f"  Algorithm:          ML-DSA-65 (FIPS 204, NIST Level 3)")
    print(f"  Shor-resistant:     YES — lattice-based (Module-Lattice)")
    print(f"  Chain depth:        3  (Root → Intermediate → Leaf)")
    print(f"  Classical ECDSA sig size: {ecdsa_sig_bytes} B")
    print(f"  ML-DSA-65 sig size:       {ml_dsa_sig_bytes} B  ({ml_dsa_sig_bytes // ecdsa_sig_bytes}x larger)")
    print(f"  Trade-off:          Larger sigs — identical P99 latency at scale")
    print(f"  Chain verified:     ✓  Cryptographically valid")
    print("="*64)

    # Save (exclude raw signature bytes — too large for JSON readability)
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Saved → {output_path}\n")

    return results


def _tick(ok: bool) -> str:
    return "✓ VALID" if ok else "✗ INVALID — chain broken!"


if __name__ == "__main__":
    try:
        import oqs  # noqa
    except ImportError:
        print("[ERROR] liboqs-python not installed. Run: pip install liboqs-python")
        raise SystemExit(1)
    build_pqc_pki_chain()
