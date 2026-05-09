"""
Crypto-Agility Engine
Demonstrates algorithm-as-config pattern — swap PQC algorithms via config.yaml
without changing application code. This is the enterprise pattern EY recommends.
"""

import yaml
import oqs
import time
import pathlib


def load_config(config_path: str = "config/crypto_config.yaml") -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)["crypto"]


class CryptoAgilityEngine:
    """
    Algorithm-agnostic cryptographic engine.
    Algorithms configured externally — change config.yaml, not code.
    """

    def __init__(self, config_path: str = "config/crypto_config.yaml"):
        cfg = load_config(config_path)
        self.kem_algorithm = cfg["kem"]["algorithm"]
        self.sig_algorithm = cfg["sig"]["algorithm"]
        self.profile = cfg.get("profile", "standard")
        print(f"CryptoAgilityEngine initialised")
        print(f"  Profile  : {self.profile}")
        print(f"  KEM      : {self.kem_algorithm}")
        print(f"  Signature: {self.sig_algorithm}")

    def key_exchange(self) -> tuple:
        """Perform key encapsulation using configured KEM algorithm."""
        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            pub = kem.generate_keypair()
            ct, ss = kem.encap_secret(pub)
        return pub, ct, ss

    def sign(self, message: bytes) -> tuple:
        """Sign a message using configured signature algorithm."""
        with oqs.Signature(self.sig_algorithm) as signer:
            pub = signer.generate_keypair()
            sig = signer.sign(message)
        return pub, sig

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature using configured signature algorithm."""
        with oqs.Signature(self.sig_algorithm) as verifier:
            return verifier.verify(message, signature, public_key)

    def benchmark(self, iterations: int = 100) -> dict:
        """Benchmark current configuration."""
        # KEM benchmark
        t0 = time.perf_counter()
        for _ in range(iterations):
            pub, ct, ss = self.key_exchange()
        kem_ms = (time.perf_counter() - t0) / iterations * 1000

        # Sig benchmark
        msg = b"benchmark_message"
        t0 = time.perf_counter()
        for _ in range(iterations):
            pub_sig, sig = self.sign(msg)
        sig_ms = (time.perf_counter() - t0) / iterations * 1000

        return {
            "profile": self.profile,
            "kem_algorithm": self.kem_algorithm,
            "sig_algorithm": self.sig_algorithm,
            "kem_avg_ms": round(kem_ms, 4),
            "sig_avg_ms": round(sig_ms, 4),
            "kem_pubkey_bytes": len(pub),
            "sig_pubkey_bytes": len(pub_sig),
            "ciphertext_bytes": len(ct),
            "signature_bytes": len(sig)
        }


if __name__ == "__main__":
    print("=== Crypto-Agility Demo ===")
    print("Change config/crypto_config.yaml to switch algorithms\n")

    engine = CryptoAgilityEngine()
    results = engine.benchmark()

    print(f"\nBenchmark results:")
    for k, v in results.items():
        print(f"  {k}: {v}")

    print("\nTo switch to IoT profile (Falcon-512):")
    print("  Edit config/crypto_config.yaml -> profile: iot")
    print("  Re-run — zero code changes required")
