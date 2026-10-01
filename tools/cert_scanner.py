"""
Certificate Scanner — PKI Quantum Vulnerability Assessment
Scans PEM certificate files and outputs migration priority list.
Context: Phase 1 of PQC migration — PKI crypto-inventory for clinical systems
"""

import pathlib
import json
import datetime
import argparse
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

ALGORITHM_RISK = {
    "RSA": {
        "quantum_safe": False, "priority": "HIGH",
        "replacement": "ML-DSA-65 (signing) or ML-KEM-768 (encryption)",
        "reason": "Broken by Shor's algorithm — all key sizes vulnerable"
    },
    "EC": {
        "quantum_safe": False, "priority": "HIGH",
        "replacement": "ML-DSA-65 (for ECDSA) / X25519+ML-KEM-768 hybrid (for ECDH)",
        "reason": "Elliptic curve discrete log broken by Shor's algorithm"
    },
    "DSA": {
        "quantum_safe": False, "priority": "HIGH",
        "replacement": "ML-DSA-65",
        "reason": "Discrete log broken by Shor's algorithm"
    },
}


def assess_certificate(cert_path: pathlib.Path) -> dict:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except Exception as e:
        return {"file": str(cert_path), "error": str(e)}

    pub_key = cert.public_key()
    now = datetime.datetime.now(datetime.timezone.utc)

    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(
            tzinfo=datetime.timezone.utc)

    days_remaining = (not_after - now).days
    years_remaining = days_remaining / 365

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_detail = f"RSA-{pub_key.key_size}"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type = "EC"
        key_detail = f"ECDSA-{pub_key.curve.name}"
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_type = "DSA"
        key_detail = "DSA"
    else:
        key_type = "UNKNOWN"
        key_detail = "Unknown"

    risk = ALGORITHM_RISK.get(key_type, {
        "quantum_safe": None, "priority": "REVIEW",
        "replacement": "Manual review required",
        "reason": "Algorithm not in vulnerability database"
    })

    # Escalate priority for long-lived certificates
    priority = risk["priority"]
    if not risk["quantum_safe"] and years_remaining > 5:
        priority = "CRITICAL"
        urgency = "Immediate re-issuance recommended — HNDL window exceeds 5 years"
    elif not risk["quantum_safe"] and years_remaining > 2:
        priority = "HIGH"
        urgency = "Prioritise in next certificate renewal cycle"
    elif not risk["quantum_safe"]:
        priority = "MEDIUM"
        urgency = "Include in planned migration — expires within 2 years"
    else:
        urgency = "No action required"

    return {
        "file": str(cert_path),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "algorithm": key_detail,
        "key_type_family": key_type,
        "quantum_safe": risk["quantum_safe"],
        "days_remaining": days_remaining,
        "years_remaining": round(years_remaining, 1),
        "not_valid_after": not_after.isoformat(),
        "priority": priority,
        "urgency": urgency,
        "replacement": risk.get("replacement", "Review required"),
        "reason": risk.get("reason", "")
    }


def scan_certificates(target_dir: str, output_path: str = "results/cert_scan.json"):
    target = pathlib.Path(target_dir)
    cert_files = list(target.rglob("*.pem")) + list(target.rglob("*.crt")) + \
                 list(target.rglob("*.cer"))

    print(f"Found {len(cert_files)} certificate files in {target}")
    results = [assess_certificate(f) for f in cert_files]

    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
                      "REVIEW": 4, "NONE": 5}
    results.sort(key=lambda x: (
        priority_order.get(x.get("priority", "REVIEW"), 9),
        -x.get("days_remaining", 0)
    ))

    report = {
        "generated": datetime.datetime.now().isoformat(),
        "scan_target": str(target.resolve()),
        "summary": {
            "total_certs": len(results),
            "quantum_vulnerable": sum(1 for r in results
                                      if r.get("quantum_safe") is False),
            "critical": sum(1 for r in results if r.get("priority") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("priority") == "HIGH"),
            "medium": sum(1 for r in results if r.get("priority") == "MEDIUM"),
        },
        "certificates": results
    }

    pathlib.Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nCertificate scan complete:")
    print(f"  Vulnerable: {report['summary']['quantum_vulnerable']}/{len(results)}")
    print(f"  Critical:   {report['summary']['critical']}")
    print(f"  High:       {report['summary']['high']}")
    print(f"  Report:     {output_path}")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="./certs")
    parser.add_argument("--output", default="results/cert_scan.json")
    args = parser.parse_args()
    scan_certificates(args.target, args.output)
