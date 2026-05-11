"""
tools/quantum_risk_scorer.py — HealthPQC v2.0
Quantum risk assessment: org crypto profile → risk score + migration urgency.

H3 FIX: Shor-vulnerable algos have risk floor of 40 regardless of data lifetime
H4 FIX: results/ directory created automatically (no FileNotFoundError)
"""

import argparse
import json
import os
import sys

# ---------------------------------------------------------------------------
# Algorithm risk database
# ---------------------------------------------------------------------------
VULNERABLE_ALGORITHMS = {
    # Shor's algorithm breaks all of these on a CRQC
    "RSA-512":    {"base_risk": 100, "broken_by": "Shor", "replacement": "ML-KEM-768"},
    "RSA-1024":   {"base_risk": 100, "broken_by": "Shor", "replacement": "ML-KEM-768"},
    "RSA-2048":   {"base_risk": 90,  "broken_by": "Shor", "replacement": "ML-KEM-768"},
    "RSA-4096":   {"base_risk": 75,  "broken_by": "Shor", "replacement": "ML-KEM-1024"},
    "ECDSA":      {"base_risk": 90,  "broken_by": "Shor", "replacement": "ML-DSA-65"},
    "ECDH":       {"base_risk": 90,  "broken_by": "Shor", "replacement": "ML-KEM-768"},
    "DH":         {"base_risk": 85,  "broken_by": "Shor", "replacement": "ML-KEM-768"},
    "DSA":        {"base_risk": 90,  "broken_by": "Shor", "replacement": "ML-DSA-65"},
    # Grover's algorithm halves the security level (not fully broken)
    "AES-128":    {"base_risk": 40,  "broken_by": "Grover (128→64 bits)", "replacement": "AES-256"},
    "AES-192":    {"base_risk": 20,  "broken_by": "Grover (192→96 bits)", "replacement": "AES-256"},
    "SHA-1":      {"base_risk": 95,  "broken_by": "Collision + Grover",   "replacement": "SHA-384"},
    "SHA-256":    {"base_risk": 20,  "broken_by": "Grover (256→128 bits)","replacement": "SHA-384"},
    "MD5":        {"base_risk": 100, "broken_by": "Collision (classical)","replacement": "SHA-256"},
}

# Algorithms that are currently quantum-safe (informational)
QUANTUM_SAFE_ALGORITHMS = {
    "AES-256", "SHA-384", "SHA-512",
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "Falcon-512", "Falcon-1024",
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-256s",
    "Kyber512", "Kyber768", "Kyber1024",
}

# Compliance deadlines by sector (year)
SECTOR_DEADLINES = {
    "healthcare":   {"apra_cpg234": 2030, "nist_ir8547": 2030, "nsw_health": 2028, "my_health_records": 2028},
    "banking":      {"apra_cpg234": 2030, "pci_dss": 2029, "swift": 2030, "austpaynet": 2028},
    "government":   {"asd_ism": 2027, "cnsa_2": 2030, "nist_ir8547": 2030},
    "telco":        {"nist_ir8547": 2030, "acma": 2031},
    "defence":      {"asd_ism": 2025, "cnsa_2": 2026},
    "insurance":    {"apra_cpg234": 2030, "privacy_act": 2029},
}

VALID_SECTORS = list(SECTOR_DEADLINES.keys())


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------
def score_algorithm(algo: str, data_lifetime_years: int) -> dict:
    """
    Score one algorithm.
    H3 FIX:
      - lifetime multiplier has floor at 0.5 (even 1-year data is at risk)
      - Shor-vulnerable algorithms have absolute floor of 40
    """
    # Quantum-safe check
    if algo in QUANTUM_SAFE_ALGORITHMS:
        return {
            "algorithm":           algo,
            "base_risk":           0,
            "data_lifetime_years": data_lifetime_years,
            "adjusted_risk_score": 0,
            "severity":            "SAFE",
            "broken_by":           "N/A",
            "replacement":         "No change required",
            "action":              "Quantum-safe — no migration needed",
        }

    if algo not in VULNERABLE_ALGORITHMS:
        return {
            "algorithm":           algo,
            "base_risk":           0,
            "data_lifetime_years": data_lifetime_years,
            "adjusted_risk_score": 0,
            "severity":            "UNKNOWN",
            "broken_by":           "Unknown",
            "replacement":         "Manual review required",
            "action":              f"Unknown algorithm '{algo}' — review manually",
        }

    meta     = VULNERABLE_ALGORITHMS[algo]
    base     = meta["base_risk"]
    broken   = meta["broken_by"]
    replace  = meta["replacement"]

    # H3 FIX: floor at 0.5 — even short-lived data remains at HNDL risk
    multiplier     = max(min(data_lifetime_years / 10.0, 2.0), 0.5)
    adjusted_risk  = min(int(base * multiplier), 100)

    # H3 FIX: Shor-vulnerable algos never score below 40
    if "Shor" in broken:
        adjusted_risk = max(adjusted_risk, 40)

    if adjusted_risk >= 80:
        severity = "CRITICAL"
        action   = f"Replace {algo} immediately — HNDL attack viable today"
    elif adjusted_risk >= 60:
        severity = "HIGH"
        action   = f"Replace {algo} within 12 months — HNDL risk active"
    elif adjusted_risk >= 40:
        severity = "MEDIUM"
        action   = f"Plan {algo} migration within 24 months"
    else:
        severity = "LOW"
        action   = f"Monitor {algo} — review at next architecture cycle"

    return {
        "algorithm":           algo,
        "base_risk":           base,
        "data_lifetime_years": data_lifetime_years,
        "lifetime_multiplier": round(multiplier, 2),
        "adjusted_risk_score": adjusted_risk,
        "severity":            severity,
        "broken_by":           broken,
        "replacement":         replace,
        "action":              action,
    }


def score_organisation(profile: dict) -> dict:
    """Full org risk assessment from profile dict."""
    results = [score_algorithm(a, profile["data_lifetime_years"])
               for a in profile["algorithms"]]

    critical = [r for r in results if r["severity"] == "CRITICAL"]
    high     = [r for r in results if r["severity"] == "HIGH"]
    medium   = [r for r in results if r["severity"] == "MEDIUM"]

    org_risk = ("CRITICAL" if critical else
                "HIGH"     if high     else
                "MEDIUM"   if medium   else "LOW")

    sector    = profile.get("sector", "banking")
    deadlines = SECTOR_DEADLINES.get(sector, {})
    nearest   = min(deadlines.values()) if deadlines else 2030

    recommendation = (
        "Immediate migration required — data already exposed to HNDL attacks"
        if org_risk == "CRITICAL" else
        "Begin hybrid migration within 6 months — high HNDL risk"
        if org_risk == "HIGH" else
        "Inventory complete — begin formal roadmap planning"
        if org_risk == "MEDIUM" else
        "Low immediate risk — monitor NIST deprecation timeline"
    )

    return {
        "organisation":              profile["name"],
        "sector":                    sector,
        "data_lifetime_years":       profile["data_lifetime_years"],
        "overall_risk":              org_risk,
        "nearest_compliance_deadline": nearest,
        "compliance_deadlines":      deadlines,
        "algorithms_assessed":       results,
        "critical_count":            len(critical),
        "high_count":                len(high),
        "medium_count":              len(medium),
        "recommendation":            recommendation,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_report(report: dict):
    print("\n" + "="*64)
    print(f"  QUANTUM RISK ASSESSMENT — {report['organisation']}")
    print("="*64)
    print(f"  Sector:               {report['sector'].upper()}")
    print(f"  Data lifetime:        {report['data_lifetime_years']} years")
    print(f"  Overall risk:         {report['overall_risk']}")
    print(f"  Nearest deadline:     {report['nearest_compliance_deadline']}")
    print(f"  Recommendation:       {report['recommendation']}")
    print("\n  ALGORITHM BREAKDOWN:")
    print("-"*64)
    width = max(len(r["algorithm"]) for r in report["algorithms_assessed"])
    for r in report["algorithms_assessed"]:
        score_str = f"score={r['adjusted_risk_score']:3d}" if r["severity"] != "SAFE" else "score= QS"
        print(f"  [{r['severity']:8s}] {r['algorithm']:{width}s}  {score_str}  → {r['action']}")
    print("="*64)

    print("\n  COMPLIANCE DEADLINES:")
    for framework, year in report["compliance_deadlines"].items():
        print(f"  {framework:25s}  {year}")
    print()


def save_report(report: dict, output_path: str):
    # H4 FIX: create results/ directory if missing
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  Full report → {output_path}")


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def validate_profile(profile: dict) -> None:
    required = {"name", "sector", "data_lifetime_years", "algorithms"}
    missing  = required - set(profile.keys())
    if missing:
        print(f"[ERROR] Profile JSON missing keys: {missing}")
        print(f"  Required: {required}")
        raise SystemExit(1)

    if not isinstance(profile["algorithms"], list) or len(profile["algorithms"]) == 0:
        print("[ERROR] 'algorithms' must be a non-empty list of strings.")
        raise SystemExit(1)

    if not isinstance(profile["data_lifetime_years"], (int, float)):
        print("[ERROR] 'data_lifetime_years' must be a number.")
        raise SystemExit(1)

    if profile["sector"] not in SECTOR_DEADLINES:
        print(f"[WARNING] Unknown sector '{profile['sector']}'. "
              f"Valid: {VALID_SECTORS}. Defaulting to 'banking'.")
        profile["sector"] = "banking"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
DEMO_PROFILE = {
    "name":                 "QuantumBank AU (Demo)",
    "sector":               "banking",
    "data_lifetime_years":  15,
    "algorithms":           ["RSA-2048", "ECDH", "AES-128", "SHA-256", "RSA-4096", "AES-256", "ML-KEM-768"],
}

HEALTHCARE_DEMO = {
    "name":                 "SWSLHD Healthcare Demo",
    "sector":               "healthcare",
    "data_lifetime_years":  25,
    "algorithms":           ["RSA-2048", "ECDH", "AES-128", "SHA-1", "ML-KEM-768"],
}


def main():
    parser = argparse.ArgumentParser(description="HealthPQC v2.0 — Quantum Risk Scorer")
    parser.add_argument("--profile", help="Path to org profile JSON file", default=None)
    parser.add_argument("--demo",    action="store_true", help="Run banking demo profile")
    parser.add_argument("--health",  action="store_true", help="Run healthcare demo profile")
    parser.add_argument("--output",  default="results/quantum_risk_report.json")
    args = parser.parse_args()

    if args.health:
        profile = HEALTHCARE_DEMO
    elif args.demo or not args.profile:
        profile = DEMO_PROFILE
    else:
        with open(args.profile) as f:
            profile = json.load(f)

    validate_profile(profile)
    report = score_organisation(profile)
    print_report(report)
    save_report(report, args.output)


if __name__ == "__main__":
    main()
