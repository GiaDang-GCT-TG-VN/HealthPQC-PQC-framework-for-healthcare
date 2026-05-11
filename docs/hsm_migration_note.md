# HSM Migration Note — PQC Transition Context

## What HealthPQC Covers

| Component | Location | Purpose |
|-----------|----------|---------|
| Algorithm benchmarking | `benchmarks/` | ML-KEM, ML-DSA, Falcon performance data |
| Hybrid TLS key exchange | `tls/` | X25519 + ML-KEM-768 latency comparison |
| Certificate lifecycle | `tools/pqc_pki_demo.py` | Root → Intermediate → Leaf chain |
| Crypto-agility API | `govapi/` | Zero-downtime algorithm swap via SIGHUP |
| Crypto inventory | `tools/cbom_scanner.py` | CycloneDX 1.6 CBOM generation |

---

## HSM Context for Migration Planning

Hardware Security Modules (HSMs) are the **trust anchor** for enterprise PKI. All root CA private keys live inside HSMs — they never leave the hardware boundary.

The **PKCS#11 interface** (demonstrated in `tools/hsm_demo.py` with SoftHSM2) is identical across:

| HSM Vendor | Product | PKCS#11 Support |
|------------|---------|-----------------|
| SoftHSM2 | Open-source | ✅ Full |
| Thales | Luna Network HSM 7 | ✅ Full |
| Entrust | nShield Connect | ✅ Full |
| Utimaco | SecurityServer | ✅ Full |
| AWS | CloudHSM | ✅ Full |

The only difference is the `.so` library path. Application code using PKCS#11 works unchanged across all vendors.

---

## Current HSM PQC Ceiling (2026)

### FIPS 140-3 Status

- **FIPS 140-3** is the certification standard for cryptographic modules
- **CMVP** (Cryptographic Module Validation Program) certifies HSM firmware
- **Status**: FIPS 140-3 PQC validation is **in progress** for major vendors
- **Ceiling**: ML-KEM and ML-DSA cannot be used inside a FIPS-validated HSM until vendor firmware receives CMVP certification

### Vendor Timeline Estimates

| Vendor | PQC HSM Target | Notes |
|--------|----------------|-------|
| Thales Luna | H2 2027 | Announced roadmap |
| Entrust nShield | 2027-2028 | Following NIST timeline |
| Utimaco | 2027 | Public commitment |
| AWS CloudHSM | TBD | Dependent on NIST finalization |

---

## What This Means for Migration Planning

### Phase 1-3 (Months 1-18): No HSM Dependency

These migrations can proceed immediately:

| Layer | Migration | HSM Required? |
|-------|-----------|---------------|
| TLS 1.3 | X25519 → Hybrid (X25519 + ML-KEM-768) | No |
| Application crypto | RSA-2048 → ML-KEM-768 | No |
| Code signing | ECDSA → ML-DSA-65 | No |
| API authentication | JWT RSA → JWT ML-DSA | No |

### Phase 4 (Months 18-36): HSM-Dependent

These migrations are **blocked until FIPS 140-3 PQC HSMs are certified**:

| Asset | Current | Target | Blocker |
|-------|---------|--------|---------|
| Root CA private key | RSA-4096 in HSM | ML-DSA-87 in HSM | FIPS 140-3 validation |
| Intermediate CA | ECDSA-P384 in HSM | ML-DSA-65 in HSM | FIPS 140-3 validation |
| Payment HSM (banking) | 3DES/AES in Thales payShield | AES-256 + PQC KEK | PCI HSM + AusPayNet IAC |

### Recommended Approach

1. **Months 1-12**: Complete TLS and application layer migration (no HSM)
2. **Months 12-18**: Prepare HSM migration runbook (vendor coordination)
3. **Months 18-24**: Pilot PQC HSM with non-production workloads
4. **Months 24-36**: Root CA re-key (requires certificate re-issuance cascade)

---

## Artefact: SoftHSM2 Demo

The `tools/hsm_demo.py` script demonstrates the PKCS#11 workflow:

```bash
# Install SoftHSM2
brew install softhsm     # macOS
sudo apt install softhsm2  # Ubuntu

# Initialize token
softhsm2-util --init-token --slot 0 \
  --label "QuantumBank-HSM" --pin 1234 --so-pin 5678

# Run demo
python tools/hsm_demo.py
```

The script:
- Connects to SoftHSM2 via PKCS#11
- Lists existing keys in the token
- Generates an ECDSA P-256 key (simulating pre-migration state)
- Prints PQC migration context and timeline

**Real HSM engagement would use identical API calls** — only the `.so` path changes.

---

## References

- NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes
- NIST IR 8547: Transition to Post-Quantum Cryptography Standards (Draft)
- FIPS 140-3: Security Requirements for Cryptographic Modules
- APRA CPG 234: Information Security (Australian banking)
- NSW Health Cyber Security Policy (Australian healthcare)

---

## Contact

Gia Phat Dang
PhD Candidate, Cybersecurity
Western Sydney University
quanphatgrp@gmail.com
