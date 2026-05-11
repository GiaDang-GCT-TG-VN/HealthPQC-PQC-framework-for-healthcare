"""
tools/cbom_emitter.py — HealthPQC v2.0
CycloneDX 1.6 CBOM emitter for quantum-vulnerable cryptographic findings.
Spec: https://cyclonedx.org/docs/1.6/json/
"""

import json
import uuid
import os
from datetime import datetime, timezone

# CycloneDX 1.6 algorithm metadata
# nistQuantumSecurityLevel: 0 = not quantum-safe, 1-5 = NIST security level
ALGO_META = {
    # Quantum-vulnerable — Shor's algorithm breaks these
    "RSA-512":    {"primitive": "asymmetric-encryption", "paramSet": "512",  "classicalBits": 56,  "nistLevel": 0},
    "RSA-1024":   {"primitive": "asymmetric-encryption", "paramSet": "1024", "classicalBits": 80,  "nistLevel": 0},
    "RSA-2048":   {"primitive": "asymmetric-encryption", "paramSet": "2048", "classicalBits": 112, "nistLevel": 0},
    "RSA-4096":   {"primitive": "asymmetric-encryption", "paramSet": "4096", "classicalBits": 140, "nistLevel": 0},
    "DSA":        {"primitive": "signature",              "paramSet": "1024", "classicalBits": 80,  "nistLevel": 0},
    "ECDSA":      {"primitive": "signature",              "paramSet": "P-256","classicalBits": 128, "nistLevel": 0},
    "ECDSA-P256": {"primitive": "signature",              "paramSet": "P-256","classicalBits": 128, "nistLevel": 0},
    "ECDSA-P384": {"primitive": "signature",              "paramSet": "P-384","classicalBits": 192, "nistLevel": 0},
    "ECDH":       {"primitive": "key-agree",              "paramSet": "P-256","classicalBits": 128, "nistLevel": 0},
    "ECDH-P256":  {"primitive": "key-agree",              "paramSet": "P-256","classicalBits": 128, "nistLevel": 0},
    "DH":         {"primitive": "key-agree",              "paramSet": "2048", "classicalBits": 112, "nistLevel": 0},
    # Grover-weakened — symmetric, key size halved
    "AES-128":    {"primitive": "block-cipher",           "paramSet": "128",  "classicalBits": 128, "nistLevel": 0},
    "AES-192":    {"primitive": "block-cipher",           "paramSet": "192",  "classicalBits": 192, "nistLevel": 1},
    "AES-256":    {"primitive": "block-cipher",           "paramSet": "256",  "classicalBits": 256, "nistLevel": 1},
    "SHA-1":      {"primitive": "hash",                   "paramSet": "160",  "classicalBits": 80,  "nistLevel": 0},
    "SHA-256":    {"primitive": "hash",                   "paramSet": "256",  "classicalBits": 128, "nistLevel": 1},
    "SHA-384":    {"primitive": "hash",                   "paramSet": "384",  "classicalBits": 192, "nistLevel": 1},
    "SHA-512":    {"primitive": "hash",                   "paramSet": "512",  "classicalBits": 256, "nistLevel": 1},
    # NIST FIPS 203 — quantum-safe KEM
    "ML-KEM-512":  {"primitive": "kem", "paramSet": "512",  "classicalBits": 128, "nistLevel": 1},
    "ML-KEM-768":  {"primitive": "kem", "paramSet": "768",  "classicalBits": 178, "nistLevel": 3},
    "ML-KEM-1024": {"primitive": "kem", "paramSet": "1024", "classicalBits": 220, "nistLevel": 5},
    "Kyber512":    {"primitive": "kem", "paramSet": "512",  "classicalBits": 128, "nistLevel": 1},
    "Kyber768":    {"primitive": "kem", "paramSet": "768",  "classicalBits": 178, "nistLevel": 3},
    "Kyber1024":   {"primitive": "kem", "paramSet": "1024", "classicalBits": 220, "nistLevel": 5},
    # NIST FIPS 204 — quantum-safe signatures
    "ML-DSA-44":  {"primitive": "signature", "paramSet": "44", "classicalBits": 128, "nistLevel": 2},
    "ML-DSA-65":  {"primitive": "signature", "paramSet": "65", "classicalBits": 178, "nistLevel": 3},
    "ML-DSA-87":  {"primitive": "signature", "paramSet": "87", "classicalBits": 220, "nistLevel": 5},
    # NIST FIPS 206 — Falcon
    "Falcon-512":  {"primitive": "signature", "paramSet": "512",  "classicalBits": 103, "nistLevel": 1},
    "Falcon-1024": {"primitive": "signature", "paramSet": "1024", "classicalBits": 230, "nistLevel": 5},
    # NIST FIPS 205 — SLH-DSA
    "SLH-DSA-SHA2-128s": {"primitive": "signature", "paramSet": "128s", "classicalBits": 128, "nistLevel": 1},
    "SLH-DSA-SHA2-256s": {"primitive": "signature", "paramSet": "256s", "classicalBits": 256, "nistLevel": 5},
}


def finding_to_component(finding: dict) -> dict:
    """
    Convert one scanner finding dict to a CycloneDX 1.6 cryptographic-asset component.

    finding must contain:
        algorithm (str): e.g. "RSA-2048"
        file      (str): source file path
        line      (int or str): line number — ALWAYS stored as str in CycloneDX 1.6
        context   (str, optional): surrounding code snippet
    """
    algo = finding.get("algorithm", "UNKNOWN")
    meta = ALGO_META.get(algo, {
        "primitive": "unknown",
        "paramSet":  "unknown",
        "classicalBits": 0,
        "nistLevel": 0,
    })

    return {
        "type": "cryptographic-asset",
        "bom-ref": str(uuid.uuid4()),
        "name": algo,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive":                meta["primitive"],
                "parameterSetIdentifier":   meta["paramSet"],
                "executionEnvironment":     "software",
                "implementationPlatform":   "unknown",
                "certificationLevel":       [],
                "classicalSecurityLevel":   meta["classicalBits"],
                "nistQuantumSecurityLevel": meta["nistLevel"],  # 0 = not quantum-safe
            },
            "oid": "",
        },
        "evidence": {
            "occurrences": [
                {
                    "location":          finding.get("file", "unknown"),
                    "line":              str(finding.get("line", 0)),   # C3 FIX: must be str
                    "confidence":        1.0,
                    "additionalContext": str(finding.get("context", ""))[:120],
                }
            ]
        },
    }


def emit_cyclonedx_cbom(
    findings: list,
    tool_name: str = "HealthPQC",
    tool_version: str = "2.0.0",
    target: str = "scanned-codebase",
) -> dict:
    """
    Wrap a list of findings in a valid CycloneDX 1.6 BOM envelope.
    Returns the full CBOM dict — call save_cbom() to write to disk.
    """
    return {
        "bomFormat":    "CycloneDX",
        "specVersion":  "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version":      1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "type":        "application",
                    "name":        tool_name,
                    "version":     tool_version,
                    "description": "Post-Quantum Cryptography scanner for healthcare and enterprise infrastructure",
                    "externalReferences": [
                        {
                            "type": "vcs",
                            "url":  "https://github.com/GiaDang-GCT-TG-VN/HealthPQC-PQC-framework-for-healthcare",
                        }
                    ],
                }
            ],
            "component": {
                "type": "application",
                "name": target,
            },
        },
        "components": [finding_to_component(f) for f in findings],
    }


def save_cbom(
    findings: list,
    output_path: str = "results/cbom_cyclonedx_v1.6.json",
    target: str = "scanned-codebase",
    tool_version: str = "2.0.0",
) -> dict:
    """Emit CycloneDX 1.6 CBOM and write to disk. Returns the cbom dict."""
    cbom = emit_cyclonedx_cbom(findings, tool_version=tool_version, target=target)
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(cbom, f, indent=2)

    quantum_safe     = sum(1 for c in cbom["components"] if c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] > 0)
    quantum_unsafe   = len(cbom["components"]) - quantum_safe

    print(f"\n[HealthPQC v2.0] CycloneDX 1.6 CBOM written → {output_path}")
    print(f"  Serial:          {cbom['serialNumber']}")
    print(f"  Target:          {target}")
    print(f"  Total findings:  {len(findings)}")
    print(f"  Quantum-safe:    {quantum_safe}")
    print(f"  NOT safe:        {quantum_unsafe}  ← migrate these")
    return cbom


# ---------------------------------------------------------------------------
# Standalone demo / smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    demo_findings = [
        {"algorithm": "RSA-2048",   "file": "app/auth.py",       "line": 14,  "context": "rsa.generate_private_key(65537, 2048)"},
        {"algorithm": "ECDH",       "file": "app/tls.py",        "line": 38,  "context": "ec.generate_private_key(ec.SECP256R1())"},
        {"algorithm": "AES-128",    "file": "app/encrypt.py",    "line": 72,  "context": "AES.new(key, AES.MODE_CBC)"},
        {"algorithm": "SHA-256",    "file": "app/hash_util.py",  "line": 5,   "context": "hashlib.sha256(data)"},
        {"algorithm": "ML-KEM-768", "file": "app/pqc_handler.py","line": 3,   "context": "oqs.KeyEncapsulation('ML-KEM-768')"},
    ]
    save_cbom(demo_findings, target="HealthPQC-demo-scan")
