"""
Full PQC Parameter Sweep
Benchmarks every available liboqs algorithm to populate the algorithm index.
"""

import oqs
import time
import csv
import os
from datetime import datetime

os.makedirs("results", exist_ok=True)
ITERATIONS = 50  # fewer iterations for full sweep


def sweep_all_kems():
    results = []
    for alg in oqs.get_enabled_kem_mechanisms():
        try:
            with oqs.KeyEncapsulation(alg) as kem:
                t0 = time.perf_counter()
                for _ in range(ITERATIONS):
                    pub = kem.generate_keypair()
                keygen_ms = (time.perf_counter() - t0) / ITERATIONS * 1000

                ct, ss = kem.encap_secret(pub)
                t0 = time.perf_counter()
                for _ in range(ITERATIONS):
                    kem.encap_secret(pub)
                encap_ms = (time.perf_counter() - t0) / ITERATIONS * 1000

            results.append({
                "algorithm": alg,
                "type": "KEM",
                "keygen_ms": round(keygen_ms, 4),
                "encap_ms": round(encap_ms, 4),
                "public_key_bytes": len(pub),
                "ciphertext_bytes": len(ct),
                "shared_secret_bytes": len(ss)
            })
            print(f"  KEM {alg}: keygen={keygen_ms:.4f}ms "
                  f"pubkey={len(pub)}B ct={len(ct)}B")
        except Exception as e:
            print(f"  SKIP {alg}: {e}")
    return results


def sweep_all_sigs():
    results = []
    message = b"benchmark_message_for_signature_testing"
    for alg in oqs.get_enabled_sig_mechanisms():
        try:
            with oqs.Signature(alg) as signer:
                t0 = time.perf_counter()
                for _ in range(ITERATIONS):
                    pub = signer.generate_keypair()
                keygen_ms = (time.perf_counter() - t0) / ITERATIONS * 1000

                sig = signer.sign(message)
                t0 = time.perf_counter()
                for _ in range(ITERATIONS):
                    signer.sign(message)
                sign_ms = (time.perf_counter() - t0) / ITERATIONS * 1000

            results.append({
                "algorithm": alg,
                "type": "SIG",
                "keygen_ms": round(keygen_ms, 4),
                "sign_ms": round(sign_ms, 4),
                "public_key_bytes": len(pub),
                "signature_bytes": len(sig)
            })
            print(f"  SIG {alg}: keygen={keygen_ms:.4f}ms "
                  f"pubkey={len(pub)}B sig={len(sig)}B")
        except Exception as e:
            print(f"  SKIP {alg}: {e}")
    return results


if __name__ == "__main__":
    print("Sweeping all KEM algorithms...")
    kem_results = sweep_all_kems()

    print("\nSweeping all Signature algorithms...")
    sig_results = sweep_all_sigs()

    all_results = kem_results + sig_results

    # Collect all unique fieldnames from KEM and SIG results
    all_fieldnames = list(dict.fromkeys(k for r in all_results for k in r.keys()))
    with open("results/full_parameter_sweep.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_fieldnames)
        writer.writeheader()
        writer.writerows(all_results)

    print(f"\nSweep complete: {len(kem_results)} KEMs, "
          f"{len(sig_results)} SIGs")
    print("Results saved to results/full_parameter_sweep.csv")
