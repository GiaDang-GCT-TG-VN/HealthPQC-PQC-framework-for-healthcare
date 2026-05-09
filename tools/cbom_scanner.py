"""
CBOM Scanner — Cryptographic Bill of Materials Generator
Scans Python codebases for quantum-vulnerable cryptographic algorithm usage.
Outputs structured JSON with migration priority and replacement recommendations.

Context: EY quantum safety engagements — Phase 1 crypto-inventory deliverable
"""

import ast
import json
import pathlib
import datetime
import argparse
from typing import Optional

# Algorithm vulnerability database
ALGORITHM_DB = {
    # Quantum-VULNERABLE algorithms (Shor's algorithm breaks these)
    "RSA": {
        "quantum_safe": False,
        "threat": "Shor's algorithm — polynomial time key recovery",
        "priority": "HIGH",
        "replacement_kem": "ML-KEM-768 (FIPS 203) for encryption",
        "replacement_sig": "ML-DSA-65 (FIPS 204) for signatures",
        "hybrid_option": "RSA + ML-KEM-768 during transition",
        "migration_urgency": "Immediate — HNDL exposure for long-lived data"
    },
    "ECDSA": {
        "quantum_safe": False,
        "threat": "Shor's algorithm — discrete log on elliptic curves",
        "priority": "HIGH",
        "replacement_sig": "ML-DSA-65 (FIPS 204)",
        "hybrid_option": "ECDSA + ML-DSA-65 during transition",
        "migration_urgency": "Immediate — used in TLS certificates and code signing"
    },
    "ECDH": {
        "quantum_safe": False,
        "threat": "Shor's algorithm — discrete log on elliptic curves",
        "priority": "HIGH",
        "replacement_kem": "X25519 + ML-KEM-768 hybrid (NIST/IETF recommended)",
        "migration_urgency": "High — all current TLS key exchange is vulnerable"
    },
    "DSA": {
        "quantum_safe": False,
        "threat": "Shor's algorithm — discrete log",
        "priority": "HIGH",
        "replacement_sig": "ML-DSA-65 (FIPS 204)",
        "migration_urgency": "Immediate — legacy algorithm, should migrate regardless"
    },
    "DH": {
        "quantum_safe": False,
        "threat": "Shor's algorithm — discrete log",
        "priority": "MEDIUM",
        "replacement_kem": "ML-KEM-768 (FIPS 203)",
        "migration_urgency": "Medium — less common in modern systems"
    },
    # Quantum-WEAKENED (Grover's provides quadratic speedup only)
    "AES": {
        "quantum_safe": True,
        "threat": "Grover's algorithm — quadratic speedup only; AES-256 remains secure",
        "priority": "LOW",
        "replacement_kem": "AES-256 (double key length from AES-128 if in use)",
        "migration_urgency": "Low — AES-256 is quantum-safe; AES-128 needs key length upgrade"
    },
    "SHA": {
        "quantum_safe": True,
        "threat": "Grover's algorithm — quadratic speedup; SHA-256/384/512 remain secure",
        "priority": "LOW",
        "replacement_sig": "SHA-256 or higher (SHA-1 should already be deprecated)",
        "migration_urgency": "Low unless using SHA-1"
    },
    # Already quantum-safe
    "ML_KEM": {"quantum_safe": True, "priority": "NONE", "fips": "203"},
    "ML_DSA": {"quantum_safe": True, "priority": "NONE", "fips": "204"},
    "FALCON": {"quantum_safe": True, "priority": "NONE", "fips": "206"},
    "SLH_DSA": {"quantum_safe": True, "priority": "NONE", "fips": "205"},
}

SEARCH_PATTERNS = {
    "RSA": ["RSA", "rsa", "PKCS1", "pkcs1"],
    "ECDSA": ["ECDSA", "ecdsa", "EC", "elliptic", "secp256", "secp384", "P256", "P384"],
    "ECDH": ["ECDH", "ecdh", "X25519", "X448"],
    "DSA": ["DSA", "dsa"],
    "DH": ["DH", "Diffie"],
    "AES": ["AES", "aes"],
    "SHA": ["SHA", "sha", "MD5", "md5"],
    "ML_KEM": ["ML_KEM", "mlkem", "ML-KEM", "Kyber"],
    "ML_DSA": ["ML_DSA", "mldsa", "ML-DSA", "Dilithium"],
    "FALCON": ["Falcon", "falcon"],
}


def classify_algorithm(name: str) -> Optional[str]:
    name_upper = name.upper().replace("-", "_").replace(" ", "_")
    for alg, patterns in SEARCH_PATTERNS.items():
        if any(p.upper() in name_upper for p in patterns):
            return alg
    return None


def scan_file(path: pathlib.Path) -> list:
    findings = []
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            alg_name = None
            line = getattr(node, "lineno", None)

            if isinstance(node, ast.Attribute):
                alg_name = node.attr
            elif isinstance(node, ast.Name):
                alg_name = node.id
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                alg_name = node.value

            if alg_name and line:
                classified = classify_algorithm(alg_name)
                if classified and classified in ALGORITHM_DB:
                    meta = ALGORITHM_DB[classified]
                    findings.append({
                        "file": str(path),
                        "line": line,
                        "detected_name": alg_name,
                        "algorithm_family": classified,
                        "quantum_safe": meta["quantum_safe"],
                        "threat": meta.get("threat", ""),
                        "priority": meta.get("priority", "UNKNOWN"),
                        "replacement": meta.get("replacement_kem",
                                        meta.get("replacement_sig", "See algorithm_index.md")),
                        "hybrid_option": meta.get("hybrid_option", "N/A"),
                        "migration_urgency": meta.get("migration_urgency", "Review required")
                    })
    except Exception as e:
        print(f"  Error scanning {path}: {e}")
    return findings


def generate_cbom(target_dir: str, output_path: str = "results/cbom_report.json"):
    target = pathlib.Path(target_dir)
    all_findings = []

    print(f"Scanning: {target.resolve()}")
    python_files = list(target.rglob("*.py"))
    print(f"Found {len(python_files)} Python files\n")

    for f in python_files:
        if ".venv" in str(f) or "node_modules" in str(f):
            continue
        findings = scan_file(f)
        if findings:
            print(f"  {f}: {len(findings)} findings")
        all_findings.extend(findings)

    # Remove duplicates (same file+line+algorithm)
    seen = set()
    unique = []
    for f in all_findings:
        key = (f["file"], f["line"], f["algorithm_family"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort by priority
    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "NONE": 3, "UNKNOWN": 4}
    unique.sort(key=lambda x: priority_order.get(x["priority"], 9))

    summary = {
        "total_findings": len(unique),
        "quantum_vulnerable": sum(1 for f in unique if not f["quantum_safe"]),
        "quantum_safe": sum(1 for f in unique if f["quantum_safe"]),
        "high_priority": sum(1 for f in unique if f["priority"] == "HIGH"),
        "medium_priority": sum(1 for f in unique if f["priority"] == "MEDIUM"),
        "low_priority": sum(1 for f in unique if f["priority"] == "LOW"),
        "files_scanned": len(python_files)
    }

    cbom = {
        "cbom_version": "1.0",
        "generated": datetime.datetime.now().isoformat(),
        "scan_target": str(target.resolve()),
        "context": "HealthPQC — Healthcare PQC Migration Framework",
        "summary": summary,
        "findings": unique
    }

    pathlib.Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as out:
        json.dump(cbom, out, indent=2)

    print(f"\n{'='*50}")
    print("CBOM Summary")
    print(f"{'='*50}")
    print(f"Files scanned:       {summary['files_scanned']}")
    print(f"Total findings:      {summary['total_findings']}")
    print(f"Quantum-vulnerable:  {summary['quantum_vulnerable']}")
    print(f"High priority:       {summary['high_priority']}")
    print(f"Medium priority:     {summary['medium_priority']}")
    print(f"Report saved to:     {output_path}")

    return cbom


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CBOM Scanner — Crypto-Inventory Tool")
    parser.add_argument("--target", default="./", help="Directory to scan")
    parser.add_argument("--output", default="results/cbom_report.json")
    args = parser.parse_args()
    generate_cbom(args.target, args.output)
