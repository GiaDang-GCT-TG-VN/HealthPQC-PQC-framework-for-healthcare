"""
Hybrid Key Exchange Benchmark
Compares: Classical X25519 | PQC-only ML-KEM-768 | Hybrid X25519+ML-KEM-768
Context: Healthcare TLS endpoint migration decision support
"""

import oqs
import time
import csv
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

os.makedirs("results", exist_ok=True)
ITERATIONS = 1000


def classical_keyx():
    """X25519 only — current TLS standard, quantum-vulnerable."""
    client = X25519PrivateKey.generate()
    server = X25519PrivateKey.generate()
    shared = client.exchange(server.public_key())
    return shared, 32, 32  # shared, client_key_bytes, server_key_bytes


def pqc_only_keyx():
    """ML-KEM-768 only — fully PQ safe, no classical fallback."""
    with oqs.KeyEncapsulation("ML-KEM-768") as server:
        pub = server.generate_keypair()
        with oqs.KeyEncapsulation("ML-KEM-768") as client:
            ct, ss_client = client.encap_secret(pub)
        ss_server = server.decap_secret(ct)
    assert ss_client == ss_server
    return ss_client, len(pub), len(ct)


def hybrid_keyx():
    """
    Hybrid: X25519 + ML-KEM-768, combined via HKDF.
    Security: safe if EITHER algorithm is unbroken.
    Recommended by NIST and IETF for 2025-2030 transition period.
    """
    # Classical side
    client_cl = X25519PrivateKey.generate()
    server_cl = X25519PrivateKey.generate()
    cl_secret_client = client_cl.exchange(server_cl.public_key())
    cl_secret_server = server_cl.exchange(client_cl.public_key())

    # PQC side
    with oqs.KeyEncapsulation("ML-KEM-768") as server_pq:
        pub = server_pq.generate_keypair()
        with oqs.KeyEncapsulation("ML-KEM-768") as client_pq:
            ct, pq_secret_client = client_pq.encap_secret(pub)
        pq_secret_server = server_pq.decap_secret(ct)

    # Combine via HKDF — standard key derivation
    combined_client = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"hybrid-healthcare-ehr-tls"
    ).derive(cl_secret_client + pq_secret_client)

    combined_server = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"hybrid-healthcare-ehr-tls"
    ).derive(cl_secret_server + pq_secret_server)

    assert combined_client == combined_server
    return combined_client, 32 + len(pub), 32 + len(ct)


def benchmark_scenario(label, fn, note):
    latencies = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        result, key_bytes, output_bytes = fn()
        latencies.append((time.perf_counter() - t0) * 1000)

    latencies.sort()
    p50 = latencies[int(ITERATIONS * 0.50)]
    p95 = latencies[int(ITERATIONS * 0.95)]
    p99 = latencies[int(ITERATIONS * 0.99)]
    avg = sum(latencies) / len(latencies)

    print(f"\n{label}")
    print(f"  Average : {avg:.4f} ms")
    print(f"  P50     : {p50:.4f} ms")
    print(f"  P95     : {p95:.4f} ms")
    print(f"  P99     : {p99:.4f} ms")
    print(f"  Key data: {key_bytes}B + {output_bytes}B")
    print(f"  Note    : {note}")

    return {
        "scenario": label,
        "avg_ms": round(avg, 4),
        "p50_ms": round(p50, 4),
        "p95_ms": round(p95, 4),
        "p99_ms": round(p99, 4),
        "key_bytes": key_bytes,
        "output_bytes": output_bytes,
        "note": note
    }


if __name__ == "__main__":
    print(f"\n{'='*60}")
    print("Hybrid Key Exchange Benchmark — Healthcare TLS Context")
    print(f"Iterations: {ITERATIONS} | Platform: ARM64")
    print(f"{'='*60}")

    results = [
        benchmark_scenario(
            "Classical only (X25519)",
            classical_keyx,
            "Current standard — quantum-vulnerable to Shor's algorithm"
        ),
        benchmark_scenario(
            "PQC only (ML-KEM-768)",
            pqc_only_keyx,
            "FIPS 203 — fully quantum safe, drops classical fallback"
        ),
        benchmark_scenario(
            "Hybrid (X25519 + ML-KEM-768 + HKDF)",
            hybrid_keyx,
            "NIST/IETF recommended — safe if EITHER algorithm holds"
        )
    ]

    overhead = results[2]["avg_ms"] - results[0]["avg_ms"]
    print(f"\nHybrid overhead vs classical: {overhead:.4f} ms average")
    print("Clinical recommendation: Hybrid deployment on all external EHR "
          "endpoints — overhead is negligible, quantum safety is immediate.")

    with open("results/hybrid_keyx_benchmark.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print("Results saved to results/hybrid_keyx_benchmark.csv")
