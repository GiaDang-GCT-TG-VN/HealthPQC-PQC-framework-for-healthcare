# Algorithm Index — PQC Algorithm Comparison Table

> Living document — updated as NIST adds new standards  
> Last updated: May 2026 | Context: EY Quantum Safety Program reference  

---

## How to use this table

This index answers: **"Which algorithm should we use for this specific use case?"**

Three dimensions drive every decision:
1. **Security level** — how much quantum safety margin do you need?
2. **Size constraints** — how large can keys and signatures/ciphertexts be?
3. **Performance** — how fast does keygen and operation need to be?

---

## Key Encapsulation Mechanisms (KEM) — Replace ECDH/RSA key exchange

| Algorithm | FIPS | Security Level | Public Key (B) | Ciphertext (B) | KeyGen (ms) | Encap (ms) | Fully PQ Safe | Hybrid Option | Recommended Use Case |
|-----------|------|---------------|---------------|----------------|-------------|------------|---------------|---------------|---------------------|
| ML-KEM-512 | 203 | L1 (AES-128) | 800 | 768 | 0.021 | 0.024 | ✅ Yes | X25519+ML-KEM-512 | Low-latency TLS, short-lived sessions |
| ML-KEM-768 | 203 | L3 (AES-192) | 1184 | 1088 | 0.022 | 0.013 | ✅ Yes | X25519+ML-KEM-768 | **Enterprise TLS — primary recommendation** |
| ML-KEM-1024 | 203 | L5 (AES-256) | 1568 | 1568 | 0.016 | 0.016 | ✅ Yes | X25519+ML-KEM-1024 | Long-term data (7-10yr retention), root key wrapping |
| HQC-128 | TBD | L1 | Large | Large | Slower | Slower | ✅ Yes | — | ML-KEM backup — code-based assumption (different math) |
| HQC-192 | TBD | L3 | Large | Large | Slower | Slower | ✅ Yes | — | ML-KEM backup at Level 3 |
| HQC-256 | TBD | TBD | Large | Large | Slower | Slower | ✅ Yes | — | ML-KEM backup at Level 5 |
| Classic McEliece | — | L1-5 | 256KB–1MB | Small | Very slow | Fast | ✅ Yes | — | Offline, archival key wrapping only — impractical for TLS |
| ECDH-P256 | — | Classical | 64 | 32 | 0.003 | 0.003 | ❌ No | → Hybrid above | **MIGRATE — Shor's algorithm breaks this** |
| X25519 | — | Classical | 32 | 32 | 0.002 | 0.002 | ❌ No | → Hybrid above | **MIGRATE — use in hybrid only during transition** |
| RSA-2048 (enc) | — | Classical | 256 | 256 | Slow | Slow | ❌ No | — | **MIGRATE NOW — Shor's algorithm breaks all key sizes** |

### KEM selection guide

```
Question 1: What is the data retention period?
  < 2 years    → ML-KEM-512 acceptable (L1)
  2-7 years    → ML-KEM-768 (L3) — standard recommendation
  7+ years     → ML-KEM-1024 (L5) — HNDL threat window requires maximum margin

Question 2: Are we in the transition period (2025-2030)?
  Yes          → Hybrid mode (classical + ML-KEM) — can't drop classical yet
  Post-2030    → Pure ML-KEM once ecosystem fully supports it

Question 3: Is bandwidth severely constrained?
  No           → ML-KEM-768 — best balance
  Yes (IoT)    → ML-KEM-512 for encryption side
```

---

## Digital Signature Algorithms (SIG) — Replace ECDSA/RSA signatures

| Algorithm | FIPS | Security Level | Public Key (B) | Signature (B) | KeyGen (ms) | Sign (ms) | Verify (ms) | Fully PQ Safe | Recommended Use Case |
|-----------|------|---------------|---------------|---------------|-------------|-----------|-------------|---------------|---------------------|
| ML-DSA-44 | 204 | L2 | 1312 | 2420 | 0.062 | 0.095 | 0.051 | ✅ Yes | Short-lived tokens, API auth, session signatures |
| ML-DSA-65 | 204 | L3 (AES-192) | 1952 | 3309 | 0.072 | 0.272 | 0.072 | ✅ Yes | **Code signing, TLS certs, PKI — primary recommendation** |
| ML-DSA-87 | 204 | L5 (AES-256) | 2592 | 4627 | 0.102 | 0.320 | 0.098 | ✅ Yes | Root CA certificates (20yr validity), critical PKI |
| Falcon-512 | 206 | L1 | 897 | 656 | 3.726 | 0.122 | 0.3 | ✅ Yes | **Medical IoT — most compact sig, 5× smaller than ML-DSA** |
| Falcon-1024 | 206 | L5 | 1793 | ~1280 | 18.4 | 1.6 | 0.6 | ✅ Yes | High-security IoT, constrained devices needing L5 |
| SLH-DSA-128s | 205 | L1 | 32 | 7856 | Fast | Very slow | Fast | ✅ Yes | Stateless — no key state management; large sigs |
| SLH-DSA-256s | 205 | L5 | 64 | 29792 | Fast | Very slow | Fast | ✅ Yes | Maximum security stateless — very large sigs |
| ECDSA-P256 | — | Classical | 64 | 64 | 0.003 | 0.005 | 0.004 | ❌ No | **MIGRATE — all current TLS certs use this** |
| RSA-2048 (sig) | — | Classical | 256 | 256 | Slow | Slow | Fast | ❌ No | **MIGRATE NOW — Shor's algorithm breaks all RSA sizes** |

### Signature algorithm selection guide

```
Question 1: What is the signature used for?
  Short-lived auth tokens     → ML-DSA-44 (L2 sufficient, fastest)
  Code signing / TLS certs    → ML-DSA-65 (L3, industry standard margin)
  Root CA / long-lived PKI    → ML-DSA-87 (L5, 20-year lifetime)
  IoT / bandwidth-constrained → Falcon-512 (666B sig vs ML-DSA-65's 3309B)

Question 2: Can I manage key state?
  Yes → ML-DSA or Falcon (simpler, stateful)
  No  → SLH-DSA (stateless, but large signatures)

Question 3: Is implementation side-channel resistance critical?
  Less critical → Falcon (complex floating-point, harder to audit)
  Critical      → ML-DSA (simpler, more auditable implementation)
```

---

## Healthcare-specific mapping

| Clinical System | Current Algorithm | Quantum Exposure | Recommended Migration | Priority | Timeline |
|----------------|-------------------|-----------------|----------------------|----------|----------|
| EHR portal (external TLS) | ECDH-P256 + ECDSA-P256 | HIGH — all sessions vulnerable | Hybrid X25519+ML-KEM-768 + ML-DSA-65 cert | HIGH | Deploy hybrid in 2025 |
| Pathology results (7yr retention) | RSA-2048 | CRITICAL — HNDL window | ML-KEM-1024 for key wrapping, re-encrypt archive | CRITICAL | Immediate |
| Medical IoT (infusion pumps, sensors) | ECDSA or proprietary | HIGH | Falcon-512 for signatures | HIGH | Next firmware cycle |
| Imaging system firmware signing | RSA-2048 | HIGH | ML-DSA-65 | HIGH | Next vendor release |
| Root CA certificate | RSA-4096 | HIGH — 20yr validity | ML-DSA-87 | HIGH | Re-issue within 12 months |
| Inter-hospital data sharing | TLS 1.2/1.3 with ECDH | HIGH | Hybrid TLS: X25519+ML-KEM-768 | HIGH | 2025 |
| At-rest patient record encryption | AES-256 | LOW — Grover halves security | Keep AES-256 (128-bit quantum security remains) | LOW | Not urgent |
| Clinical code signing pipeline | ECDSA | HIGH | ML-DSA-65 | HIGH | Next CI/CD update |

---

## Fully PQ safe vs hybrid — decision matrix

| Scenario | Use Hybrid | Use Pure PQC | Reason |
|----------|-----------|--------------|--------|
| External TLS today (2025) | ✅ | ❌ | Not all clients support PQC; hybrid gives backward compat |
| Internal system-to-system (2025) | ✅ | Optional | Control both sides, but hybrid is safer |
| Certificate issuance (2025) | Optional | ✅ | Certificates are long-lived — full PQC now avoids re-issuance |
| External TLS post-2030 | ❌ | ✅ | Ecosystem should support pure PQC by then |
| IoT device auth | Optional | ✅ | Size constraints favour pure Falcon-512 over hybrid |
| Key wrapping for archived data | ❌ | ✅ | This is exactly the HNDL use case — needs PQC now |

---

## Operational impact summary

| Metric | Classical (ECDH+ECDSA) | Hybrid PQC (X25519+ML-KEM-768) | Delta |
|--------|----------------------|-------------------------------|-------|
| TLS handshake key material | ~96B | ~2304B (1184+1088+32) | +2208B |
| Key exchange latency (single) | ~0.003ms | ~0.05ms | +0.047ms |
| P99 latency at 1000 users | baseline | baseline +2ms | Negligible |
| Certificate size (ECDSA→ML-DSA-65) | ~1KB | ~4KB | +3KB |
| Memory footprint | baseline | +15–25MB at 1000 users | Acceptable |

**Clinical recommendation**: Hybrid overhead is operationally negligible for EHR portal TLS. The risk cost of *not* migrating (HNDL exposure on patient records) far exceeds the operational cost of migration.

---

## Standards status (May 2026)

| Algorithm | Standard | Status | NIST Reference |
|-----------|----------|--------|----------------|
| ML-KEM | FIPS 203 | ✅ Final (August 2024) | csrc.nist.gov/pubs/fips/203/final |
| ML-DSA | FIPS 204 | ✅ Final (August 2024) | csrc.nist.gov/pubs/fips/204/final |
| SLH-DSA | FIPS 205 | ✅ Final (August 2024) | csrc.nist.gov/pubs/fips/205/final |
| FN-DSA (Falcon) | FIPS 206 | ✅ Final (August 2024) | csrc.nist.gov/pubs/fips/206/final |
| HQC | TBD | 🔄 Selected March 2025 — standardisation in progress | Backup KEM for ML-KEM |

---

## References

- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe — liboqs](https://openquantumsafe.org/liboqs/)
- [IETF Hybrid Key Exchange (draft)](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [NIST IR 8547 — Transition Timeline](https://csrc.nist.gov/publications/detail/nistir/8547/final)
