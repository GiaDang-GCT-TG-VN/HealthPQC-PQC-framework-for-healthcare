# HealthPQC — Post-Quantum Cryptography Framework for Healthcare

> A practical PQC implementation and migration toolkit built for clinical infrastructure
> Developed in collaboration with SWERI–Ingham Institute / SWSLHD (500K+ patient population, Sydney NSW)

---

## Project Summary

This framework provides **end-to-end tooling for Post-Quantum Cryptography migration** in healthcare environments, addressing the "Harvest Now, Decrypt Later" (HNDL) threat to patient data with 10+ year retention requirements.

### What We Built

| Component | Purpose | Output |
|-----------|---------|--------|
| **Algorithm Benchmarks** | Performance testing of NIST-standardized PQC algorithms | Real ARM64 timing data for ML-KEM, ML-DSA, Falcon |
| **Hybrid TLS Demo** | X25519 + ML-KEM-768 combined key exchange | Latency comparison: classical vs hybrid vs PQC-only |
| **CBOM Scanner** | Crypto-inventory tool using AST analysis | JSON report of quantum-vulnerable dependencies |
| **Certificate Scanner** | PKI audit for RSA/ECDSA certificates | Identifies certificates needing PQC replacement |
| **Crypto-Agility Engine** | Algorithm-as-config pattern demo | YAML-driven algorithm switching |
| **Load Testing Suite** | Concurrent user performance testing | P50/P95/P99 latency at 100–1000 users |
| **Documentation Suite** | Regulatory guidance and migration playbooks | Executive briefs, technical guides, compliance matrix |

---

## Key Results (ARM64 / Apple Silicon M-series)

### Algorithm Performance

| Algorithm | NIST FIPS | KeyGen (ms) | Public Key (B) | Output (B) | Healthcare Use Case |
|-----------|-----------|-------------|----------------|------------|---------------------|
| **ML-KEM-768** | FIPS 203 | 0.022 | 1,184 | 1,088 | EHR TLS sessions (NIST Level 3) |
| **ML-KEM-1024** | FIPS 203 | 0.016 | 1,568 | 1,568 | Long-term patient data (NIST Level 5) |
| **ML-DSA-65** | FIPS 204 | 0.072 | 1,952 | 3,309 | Clinical code signing |
| **Falcon-512** | FIPS 206 | 3.726 | 897 | 656 | Medical IoT authentication |

### Hybrid TLS Performance

| Mode | Avg Latency (ms) | P99 at 1000 Users |
|------|------------------|-------------------|
| Classical (X25519) | 0.256 | 71 ms |
| PQC-only (ML-KEM-768) | 0.045 | 70 ms |
| **Hybrid (X25519 + ML-KEM-768)** | 0.384 | 71 ms |

**Key Finding:** Hybrid PQC adds **zero measurable P99 overhead** at scale (71ms = 71ms).

### Load Test Summary (1000 Concurrent Users)

- **Total Requests:** 180,423
- **Failure Rate:** 0%
- **Hybrid vs Classical P99:** Identical (71ms)
- **Throughput:** ~1,000 RPS per endpoint

---

## Repository Structure

```
HealthPQC/
├── PQC_README.md              # This file — project summary
├── requirements.txt           # Python dependencies
├── verify_liboqs.py           # liboqs installation verification
│
├── benchmarks/
│   ├── healthcare_benchmark.py    # 6 clinical use case benchmarks
│   ├── full_parameter_sweep.py    # All 26 KEMs + 68 SIGs tested
│   └── results/                   # CSV outputs
│
├── tls/
│   ├── hybrid_keyx_benchmark.py   # X25519 vs ML-KEM vs Hybrid comparison
│   └── results/                   # Latency CSVs
│
├── tools/
│   ├── cbom_scanner.py            # AST-based crypto inventory scanner
│   ├── cert_scanner.py            # PKI certificate vulnerability scanner
│   └── crypto_agility_engine.py   # Algorithm-as-config demo
│
├── load_test/
│   ├── app.py                     # FastAPI server (3 endpoints)
│   ├── locustfile.py              # Locust load test scenarios
│   └── results/                   # P50/P95/P99 CSVs at 100/500/1000 users
│
├── config/
│   └── crypto_config.yaml         # Crypto-agility configuration
│
├── results/                       # Aggregated benchmark outputs
│   ├── healthcare_benchmark.csv
│   ├── full_parameter_sweep.csv
│   ├── hybrid_keyx_benchmark.csv
│   ├── cbom_report.json
│   └── cert_scan.json
│
└── docs/
    ├── algorithm_index.md         # Algorithm comparison with real benchmarks
    ├── liboqs_install.md          # Apple Silicon ARM64 installation guide
    ├── tls_migration_guide.md     # EHR system TLS migration walkthrough
    ├── regulatory_matrix.md       # NIST / NSA / EU / APRA compliance deadlines
    ├── performance_impact_brief.md    # Technical brief with load test data
    ├── pqc_executive_brief.md     # Executive summary for healthcare leadership
    ├── pqc_qhe_privacy_stack.md   # PQC + QHE privacy architecture
    └── sweri_engagement_summary.md    # Clinical deployment context
```

---

## Tools Developed

### 1. Healthcare Benchmark (`benchmarks/healthcare_benchmark.py`)
Benchmarks 6 clinical use cases mapping PQC algorithms to real healthcare scenarios:
- EHR TLS handshakes
- Patient record encryption (10-year retention)
- Clinical software code signing
- Medical IoT device authentication
- Root CA for hospital PKI
- Inter-hospital data exchange

### 2. Full Parameter Sweep (`benchmarks/full_parameter_sweep.py`)
Tests **all 94 algorithms** in liboqs:
- 26 Key Encapsulation Mechanisms (KEMs)
- 68 Digital Signature algorithms
- Outputs: keygen time, encap/decap or sign/verify time, key sizes

### 3. Hybrid TLS Benchmark (`tls/hybrid_keyx_benchmark.py`)
Compares three key exchange modes:
- **Classical:** X25519 only
- **PQC-only:** ML-KEM-768 only
- **Hybrid:** X25519 + ML-KEM-768 combined via HKDF

### 4. CBOM Scanner (`tools/cbom_scanner.py`)
AST-based scanner that detects quantum-vulnerable crypto usage:
- RSA, DSA, ECDSA, ECDH imports
- Prioritized JSON report (HIGH/MEDIUM/LOW)
- Scanned 225 findings in this repo alone

### 5. Certificate Scanner (`tools/cert_scanner.py`)
Scans PEM certificates for quantum vulnerability:
- Flags RSA, ECDSA, DSA algorithms
- Reports key sizes and expiration dates
- Outputs JSON remediation report

### 6. Crypto-Agility Engine (`tools/crypto_agility_engine.py`)
Demonstrates algorithm-as-config pattern:
- Reads `config/crypto_config.yaml`
- Swaps algorithms without code changes
- Foundation for zero-downtime PQC migration

### 7. Load Test Suite (`load_test/`)
FastAPI + Locust testing at scale:
- 3 endpoints: `/classical`, `/pqc-only`, `/hybrid`
- Tested at 100, 500, 1000 concurrent users
- Full P50/P95/P99/Max latency metrics

---

## Documentation Suite

| Document | Purpose |
|----------|---------|
| `algorithm_index.md` | Living comparison table with real benchmark data |
| `liboqs_install.md` | Step-by-step ARM64/Apple Silicon installation |
| `tls_migration_guide.md` | 4-phase EHR TLS migration playbook |
| `regulatory_matrix.md` | NIST, NSA, EU, APRA compliance timeline |
| `performance_impact_brief.md` | 1-page technical brief with load test results |
| `pqc_executive_brief.md` | Non-technical executive summary |
| `pqc_qhe_privacy_stack.md` | PQC + QHE combined privacy architecture |
| `sweri_engagement_summary.md` | Real-world clinical deployment context |

---

## Technology Stack

- **PQC Library:** liboqs 0.14.0 (Open Quantum Safe)
- **Algorithms:** ML-KEM (FIPS 203), ML-DSA (FIPS 204), Falcon (FIPS 206)
- **Classical Crypto:** cryptography library (X25519, HKDF)
- **Web Framework:** FastAPI + Uvicorn
- **Load Testing:** Locust
- **Platform:** Python 3.13, ARM64 (Apple Silicon)

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/GiaDang-GCT-TG-VN/HealthPQC-PQC-framework-for-healthcare
cd HealthPQC-PQC-framework-for-healthcare

# Install dependencies
pip install -r requirements.txt

# Verify liboqs installation
python verify_liboqs.py

# Run healthcare benchmarks
python benchmarks/healthcare_benchmark.py

# Run CBOM scanner
python tools/cbom_scanner.py --target ./

# Start load test server
cd load_test && uvicorn app:app --workers 4

# Run load test (separate terminal)
locust -f locustfile.py --host http://localhost:8000
```

---

## Context: PQC and QHE Relationship

This project complements PhD research in **Quantum Homomorphic Encryption (QHE)**:

| Technology | Protects Data... | Timeline |
|------------|------------------|----------|
| **PQC** | In transit and at rest | Migration required by 2030-2035 |
| **QHE** | During computation | Research frontier (5-10 years) |

Both share mathematical foundations in **lattice problems** (LWE/RLWE hardness assumptions).

---

## Professional Context

- **Clinical Deployment:** SWERI–Ingham Institute / SWSLHD (500K+ patients)
- **Academic Validation:** 3 IEEE publications in lattice-based QHE
- **Hardware Testing:** IBM Quantum (ibm_brisbane) — 96.1% correctness
- **Contact:** quanphatgrp@gmail.com | Western Sydney University

---

## License

MIT — Open for research and educational use.
