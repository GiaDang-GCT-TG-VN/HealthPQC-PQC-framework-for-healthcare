"""
Intentionally vulnerable demo code for the CBOM scanner. Do not use.

SYNTHETIC EXAMPLE — this file exists so `tools/cbom_scanner.py` has quantum-vulnerable
crypto to discover when it scans the repository. It is not imported by any other module
and is not part of the HealthPQC framework.

Every algorithm below is broken by a cryptographically relevant quantum computer:

  RSA-2048     — Shor's algorithm recovers the private key from the modulus
  ECDSA P-256  — Shor's algorithm over the elliptic-curve discrete log
  ECDH P-256   — same; the shared secret is recoverable after the fact
  SHA-1        — already classically broken (SHAttered, 2017); Grover worsens it
  AES-256-CBC  — Grover halves the effective key strength to 128 bits

The PQC replacements are benchmarked in `benchmarks/healthcare_benchmark.py`:
ML-KEM-768 for key establishment, ML-DSA-65 for signatures, SHA-384 for hashing.

No key material here is secret, persisted, or derived from real data.
"""

import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MESSAGE = b"synthetic clinical payload - not real patient data"


def rsa_2048_keygen_and_sign() -> bytes:
    """VULNERABLE: RSA-2048 signature. Replace with ML-DSA-65 (FIPS 204)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    signature = private_key.sign(
        MESSAGE,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    print(f"  RSA-2048     signature {len(signature)}B, public key {len(public_pem)}B PEM")
    return signature


def ecdsa_p256_sign() -> bytes:
    """VULNERABLE: ECDSA over P-256. Replace with ML-DSA-65 or Falcon-512."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))
    print(f"  ECDSA P-256  signature {len(signature)}B")
    return signature


def ecdh_p256_exchange() -> bytes:
    """VULNERABLE: ECDH over P-256. Replace with ML-KEM-768 (FIPS 203)."""
    alice_private = ec.generate_private_key(ec.SECP256R1())
    bob_private = ec.generate_private_key(ec.SECP256R1())

    shared = alice_private.exchange(ec.ECDH(), bob_private.public_key())
    print(f"  ECDH P-256   shared secret {len(shared)}B")
    return shared


def sha1_digest() -> str:
    """VULNERABLE: SHA-1 is collision-broken. Replace with SHA-384 or SHA3-384."""
    digest = hashlib.sha1(MESSAGE).hexdigest()
    print(f"  SHA-1        digest {digest[:16]}...")
    return digest


def aes_256_cbc_encrypt() -> bytes:
    """WEAKENED: AES-256-CBC. Grover reduces this to ~128-bit strength."""
    key = os.urandom(32)
    iv = os.urandom(16)

    padded = MESSAGE + b"\x00" * (-len(MESSAGE) % 16)
    encryptor = Cipher(algorithms.AES256(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    print(f"  AES-256-CBC  ciphertext {len(ciphertext)}B")
    return ciphertext


def main() -> None:
    print("=" * 64)
    print("  SYNTHETIC LEGACY CRYPTO — CBOM scanner target")
    print("  Intentionally vulnerable demo code. Do not use.")
    print("=" * 64)
    rsa_2048_keygen_and_sign()
    ecdsa_p256_sign()
    ecdh_p256_exchange()
    sha1_digest()
    aes_256_cbc_encrypt()
    print("-" * 64)
    print("  Scan with: python tools/cbom_scanner.py --target ./")


if __name__ == "__main__":
    main()
