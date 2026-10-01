# HealthPQC — Post-Quantum Cryptography Framework for Healthcare

![Tests](https://img.shields.io/badge/tests-53%20passed-brightgreen)
![CycloneDX](https://img.shields.io/badge/CBOM-CycloneDX%201.6-blue)
![FIPS](https://img.shields.io/badge/algorithms-FIPS%20203%20204%20206-blue)
![Python](https://img.shields.io/badge/python-3.13-blue)

> A practical PQC implementation and migration toolkit built for clinical infrastructure
> Independent research prototype motivated by long-term patient data protection in public healthcare.

---

## Project Summary

This framework provides **end-to-end tooling for Post-Quantum Cryptography migration** in healthcare environments, addressing the "Harvest Now, Decrypt Later" (HNDL) threat to patient data with 10+ year retention requirements.

### Crypto-Agility in 30 seconds

Algorithms are declared in `config/crypto_config.yaml`, never hard-coded:

```yaml
crypto:
  profile: standard  # options: standard | iot | high-security | transition

  kem:
    algorithm: ML-KEM-768  # FIPS 203 — NIST Level 3
    # Alternatives: ML-KEM-512 (Level 1), ML-KEM-1024 (Level 5), HQC-128

  sig:
    algorithm: ML-DSA-65   # FIPS 204 — NIST Level 3
    # Alternatives: ML-DSA-44, ML-DSA-87, Falcon-512, Falcon-1024
```

Swapping `ML-KEM-768` for `ML-KEM-1024` (or switching `profile` to `high-security`) changes the
algorithm in use on the next run — no code changes, no redeploy of application logic.

---

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

*(single run, Apple Silicon, not a controlled lab benchmark)*

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
| Classical (X25519) | 0.256 | 72 ms |
| PQC-only (ML-KEM-768) | 0.045 | 70 ms |
| **Hybrid (X25519 + ML-KEM-768)** | 0.384 | 72 ms |

**Key Finding:** In a local single-machine loopback test with 1000 simulated users, hybrid PQC showed
**no measurable P99 difference** compared with classical X25519. This was measured over loopback on one
machine, so it isolates compute cost only — real network conditions (RTT, MTU, packet loss, middleboxes)
may differ, and the larger hybrid handshake could show overhead there.

### Load Test Summary (1000 Concurrent Users)

- **Total Requests:** 178,149
- **Failure Rate:** 0%
- **Hybrid vs Classical P99:** Identical (72ms)
- **Throughput:** ~1,000 RPS per endpoint

---

## Repository Structure

```
HealthPQC/
├── README.md                  # This file — project summary
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
├── examples/
│   └── legacy_crypto_demo.py      # SYNTHETIC vulnerable crypto — CBOM scan target
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
│   ├── cbom_cyclonedx_v1.6.json
│   ├── cbom_legacy.json
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
    └── healthcare_context.md      # Why healthcare needs PQC
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
Import-aware AST scanner (Python) plus regex scanning for Java/Go/C#/JS:
- Detects RSA, ECDSA, ECDH, DH, AES, 3DES, SHA-1 and MD5 usage
- A call is only reported when it resolves through the file's own imports into a known
  crypto module (`cryptography`, `hashlib`, `Crypto`/`Cryptodome`, `ssl`, `oqs`), so a
  user-defined `rsa_helper()` or `ecdh_p256_exchange()` is never flagged
- Findings are deduplicated per (file, enclosing scope, algorithm family): one asset
  used across several lines of a function is one asset, and a nested expression such as
  `ec.generate_private_key(ec.SECP256R1())` is one finding whose curve refines the name
- Prioritized JSON report (HIGH/MEDIUM/LOW); `--include-safe` also lists quantum-safe usage
- Emits CycloneDX 1.6 CBOM (`results/cbom_cyclonedx_v1.6.json`)
- A scan of this repository returns **5 findings (4 HIGH, 1 MEDIUM)** — RSA-2048,
  ECDSA-P256, ECDH-P256, SHA-1 and AES-256, all from the synthetic target in
  `examples/legacy_crypto_demo.py`
- Known gap: the pattern list does not cover X25519/Ed25519, so this repo's own hybrid
  demo code is not flagged

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
| `healthcare_context.md` | Why healthcare needs PQC — retention, HNDL, EHR/PKI/IoT |

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

# Run CBOM scanner over the repo root (finds examples/legacy_crypto_demo.py)
python tools/cbom_scanner.py --target ./ --output results/cbom_cyclonedx_v1.6.json

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

## Author & Context

- **Author:** Gia Dang, PhD candidate, Western Sydney University
- **Research area:** Lattice-based Quantum Homomorphic Encryption (QHE) for healthcare data privacy
- **Academic Validation:** 2 IEEE publications in lattice-based QHE
- **Contact:** 22040062@student.westernsydney.edu.au

> **Disclaimer**
>
> This is an independent research prototype. It is not endorsed by, deployed at, or affiliated
> with Western Sydney University, SWERI, the Ingham Institute, or SWSLHD. No real patient data
> is used. Benchmarks are synthetic.

---

## License

MIT — Open for research and educational use.
