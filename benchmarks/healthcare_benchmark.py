"""
Healthcare PQC Benchmark
Evaluates all NIST-standardised PQC algorithms against clinical use cases.
Context: SWERI-Ingham Institute / SWSLHD infrastructure (500K+ patients)
"""

import oqs
import time
import csv
import json
import os
from datetime import datetime

HEALTHCARE_USE_CASES = {
    "EHR_TLS_Session": {
        "algorithm": "ML-KEM-768",
        "type": "kem",
        "fips": "203",
        "security_level": "L3",
        "requirement": "Low latency, NIST Level 3 — matches current TLS security margin",
        "constraint": "Must fit TLS 1.3 handshake without fragmentation",
        "clinical_system": "Electronic Health Record portal (external-facing)"
    },
    "Long_Term_Patient_Records": {
        "algorithm": "ML-KEM-1024",
        "type": "kem",
        "fips": "203",
        "security_level": "L5",
        "requirement": "Maximum security — 10-year data retention, HNDL threat window",
        "constraint": "Storage overhead acceptable — used for archival key wrapping",
        "clinical_system": "Patient record archive, pathology results (7–10yr retention)"
    },
    "Clinical_Code_Signing": {
        "algorithm": "ML-DSA-65",
        "type": "sig",
        "fips": "204",
        "security_level": "L3",
        "requirement": "Software update verification — NIST Level 3",
        "constraint": "Signature verified at boot/install, size less critical than IoT",
        "clinical_system": "Firmware signing for infusion pumps, imaging systems"
    },
    "Medical_IoT_Auth": {
        "algorithm": "Falcon-512",
        "type": "sig",
        "fips": "206",
        "security_level": "L1",
        "requirement": "Compact signature — bandwidth-constrained medical devices",
        "constraint": "Infusion pumps, glucose monitors, sensors: packet budget <1KB",
        "clinical_system": "IoT medical device authentication over low-bandwidth channels"
    },
    "Root_CA_Certificate": {
        "algorithm": "ML-DSA-87",
        "type": "sig",
        "fips": "204",
        "security_level": "L5",
        "requirement": "Maximum security — root CA certs valid 20 years",
        "constraint": "Signed once, verified rarely — size irrelevant",
        "clinical_system": "SWSLHD root certificate authority"
    },
    "Inter_Hospital_Key_Exchange": {
        "algorithm": "ML-KEM-768",
        "type": "kem",
        "fips": "203",
        "security_level": "L3",
        "requirement": "Secure channel for multi-hospital data sharing",
        "constraint": "Standard TLS channel — same constraints as EHR TLS",
        "clinical_system": "Cross-hospital research data sharing (SWERI protocol)"
    }
}

ITERATIONS = 100
os.makedirs("results", exist_ok=True)


def benchmark_kem(name, config):
    alg = config["algorithm"]
    with oqs.KeyEncapsulation(alg) as kem:
        # Keygen benchmark
        t0 = time.perf_counter()
        for _ in range(ITERATIONS):
            pub = kem.generate_keypair()
        keygen_ms = (time.perf_counter() - t0) / ITERATIONS * 1000

        # Encapsulation benchmark
        t0 = time.perf_counter()
        for _ in range(ITERATIONS):
            ct, ss = kem.encap_secret(pub)
        encap_ms = (time.perf_counter() - t0) / ITERATIONS * 1000

        # Decapsulation benchmark
        t0 = time.perf_counter()
        for _ in range(ITERATIONS):
            recovered = kem.decap_secret(ct)
        decap_ms = (time.perf_counter() - t0) / ITERATIONS * 1000

    return {
        "use_case": name,
        "algorithm": alg,
        "fips": config["fips"],
        "type": "KEM",
        "security_level": config["security_level"],
        "keygen_ms": round(keygen_ms, 4),
        "operation_ms": round(encap_ms, 4),
        "decap_ms": round(decap_ms, 4),
        "public_key_bytes": len(pub),
        "output_bytes": len(ct),
        "requirement": config["requirement"],
        "constraint": config["constraint"],
        "clinical_system": config["clinical_system"]
    }


def benchmark_sig(name, config):
    alg = config["algorithm"]
    message = b"clinical_update_authentication_v2.1.0_SWSLHD"
    with oqs.Signature(alg) as signer:
        # Keygen benchmark
        t0 = time.perf_counter()
        for _ in range(ITERATIONS):
            pub = signer.generate_keypair()
        keygen_ms = (time.perf_counter() - t0) / ITERATIONS * 1000

        # Sign benchmark
        t0 = time.perf_counter()
        for _ in range(ITERATIONS):
            sig = signer.sign(message)
        sign_ms = (time.perf_counter() - t0) / ITERATIONS * 1000

        # Verify benchmark
        with oqs.Signature(alg) as verifier:
            t0 = time.perf_counter()
            for _ in range(ITERATIONS):
                valid = verifier.verify(message, sig, pub)
            verify_ms = (time.perf_counter() - t0) / ITERATIONS * 1000

    return {
        "use_case": name,
        "algorithm": alg,
        "fips": config["fips"],
        "type": "SIG",
        "security_level": config["security_level"],
        "keygen_ms": round(keygen_ms, 4),
        "operation_ms": round(sign_ms, 4),
        "verify_ms": round(verify_ms, 4),
        "public_key_bytes": len(pub),
        "output_bytes": len(sig),
        "requirement": config["requirement"],
        "constraint": config["constraint"],
        "clinical_system": config["clinical_system"]
    }


def run_benchmarks():
    print(f"\n{'='*70}")
    print("HealthPQC — Clinical Use Case Benchmark")
    print(f"Platform: Apple Silicon ARM64 | Iterations: {ITERATIONS}")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    results = []
    for name, config in HEALTHCARE_USE_CASES.items():
        print(f"Benchmarking: {name} ({config['algorithm']})...")
        if config["type"] == "kem":
            result = benchmark_kem(name, config)
        else:
            result = benchmark_sig(name, config)
        results.append(result)

    # Print summary table
    print(f"\n{'Use Case':<30} {'Algorithm':<15} {'KeyGen':<10} {'Op':<10} {'PubKey':<10} {'Output'}")
    print("-" * 90)
    for r in results:
        print(f"{r['use_case']:<30} {r['algorithm']:<15} "
              f"{r['keygen_ms']:<10.4f} {r['operation_ms']:<10.4f} "
              f"{r['public_key_bytes']:<10} {r['output_bytes']}")

    # Key insight
    kem_results = [r for r in results if r["type"] == "KEM"]
    sig_results = [r for r in results if r["type"] == "SIG"]
    iot_sig = next(r for r in sig_results if "IoT" in r["use_case"])
    std_sig = next(r for r in sig_results if "Code" in r["use_case"])
    ratio = std_sig["output_bytes"] / iot_sig["output_bytes"]
    print(f"\nKey insight: {std_sig['algorithm']} sig = {std_sig['output_bytes']}B vs "
          f"{iot_sig['algorithm']} sig = {iot_sig['output_bytes']}B "
          f"({ratio:.1f}x larger — IoT choice is Falcon-512)")

    # Save CSV — collect all unique fieldnames from all results
    csv_path = "results/healthcare_benchmark.csv"
    all_fieldnames = list(dict.fromkeys(k for r in results for k in r.keys()))
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_fieldnames)
        writer.writeheader()
        writer.writerows(results)

    # Save JSON (structured)
    json_path = "results/healthcare_benchmark.json"
    with open(json_path, "w") as f:
        json.dump({
            "metadata": {
                "generated": datetime.now().isoformat(),
                "platform": "Apple Silicon ARM64",
                "iterations": ITERATIONS,
                "context": "SWERI-Ingham Institute / SWSLHD clinical infrastructure"
            },
            "results": results
        }, f, indent=2)

    print(f"\nResults saved to {csv_path} and {json_path}")
    return results


if __name__ == "__main__":
    run_benchmarks()
