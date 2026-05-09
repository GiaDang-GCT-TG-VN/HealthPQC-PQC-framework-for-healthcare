# PQC Migration for Australian Healthcare — Executive Brief

**Why 2025 is the start date, not 2030**

---

## The problem in one paragraph

Every encrypted communication in your hospital network — patient record access, inter-hospital data sharing, medical device authentication — relies on RSA or elliptic curve cryptography. A sufficiently powerful quantum computer, using Shor's algorithm, will break every one of these encryption schemes in polynomial time. The problem is not that quantum computers exist at that scale today. The problem is that adversaries are storing your encrypted data *right now*, intending to decrypt it when those computers arrive. For patient records with 7–10 year retention requirements, that data is already at risk.

---

## Why the action date is 2025, not 2030

Three compounding facts make 2025 the urgent start date:

**Fact 1: Migration takes 3–7 years.**  
A healthcare organisation with complex PKI, legacy medical devices, and multiple integrated systems cannot complete a cryptographic migration quickly. Certificate re-issuance, PKI redesign, device firmware updates, vendor coordination, and staff training compound. Conservative estimate: 5 years for a mid-size health district.

**Fact 2: NIST has set a 2030 deprecation deadline.**  
NIST IR 8547 requires US federal systems to deprecate quantum-vulnerable algorithms by 2030 and disallow them by 2035. Australian systems that connect to, supply, or receive funding from US federal health programmes fall within this scope. The EU has mandated healthcare as a "high-risk" category requiring migration by 2030.

**Fact 3: The data is already being harvested.**  
Nation-state adversaries are operating "harvest now, decrypt later" programmes — collecting encrypted medical records and research data today, storing it, and waiting for quantum decryption capability. This is not theoretical: it has been reported in intelligence community assessments. Patient data encrypted with ECDH today may be readable by a foreign adversary in the mid-2030s.

**Conclusion:** If migration takes 5 years and the deadline is 2030, the start date was 2025. Not starting immediately means missing the window.

---

## What post-quantum cryptography is (and is not)

**What it is:**  
A set of NIST-standardised mathematical algorithms that are believed to be hard for both classical and quantum computers to break. The primary standards are:
- **ML-KEM (FIPS 203)** — replaces ECDH in TLS key exchange
- **ML-DSA (FIPS 204)** — replaces ECDSA in certificates and code signing
- **Falcon/FN-DSA (FIPS 206)** — compact signatures for IoT medical devices

**What it is not:**  
- A silver bullet that requires replacing everything simultaneously
- A theoretical future concern — standards are finalised and implementations exist
- Disruptive to clinical operations when deployed correctly using a hybrid approach

---

## The hybrid approach — minimum disruption, immediate protection

The recommended transition approach is **hybrid key exchange**: running a classical algorithm (X25519) and a post-quantum algorithm (ML-KEM-768) simultaneously. The combined shared secret is secure as long as *either* algorithm is unbroken. This means:

- Clinical systems continue working with all current clients (backward compatible)
- New data encrypted after hybrid deployment is immediately protected against future quantum decryption
- No emergency re-engineering — hybrid slots into existing TLS infrastructure

**Performance impact**: Benchmarking on ARM64 hardware shows hybrid key exchange adds less than 2ms to P99 TLS handshake latency at 1,000 concurrent users — operationally negligible for an EHR portal.

---

## Four-phase migration roadmap

| Phase | Timeframe | Activity | Clinical Impact |
|-------|-----------|----------|----------------|
| 1. Discovery | Months 1–3 | Crypto-inventory: catalogue every algorithm, certificate, and encrypted dataset | None — assessment only |
| 2. Hybrid deployment | Months 3–9 | Deploy hybrid TLS on P0/P1 systems; re-issue critical certificates | Minimal — backward compatible |
| 3. Full migration | Months 9–36 | Migrate remaining systems; update medical device firmware; re-issue all certificates | Coordinated with natural renewal cycles |
| 4. Legacy remediation | Months 36–60 | PQC gateways for non-updatable devices; HSM replacement where needed | Managed — no patient-facing disruption |

---

## Australian regulatory context

| Framework | Quantum Relevance | Required Action |
|-----------|-------------------|----------------|
| Privacy Act 1988 | Patient data encryption is a privacy obligation — quantum threat is a material risk | Assess and address quantum risk in privacy impact assessments |
| APRA CPG 234 | Quantum risk explicitly in scope for health insurers | Document quantum risk assessment and migration plan |
| ACSC ISM | Encryption controls must address emerging threats | Align cryptographic controls with NIST PQC standards |
| My Health Records Act | Infrastructure encryption — quantum risk in scope | MHR infrastructure must maintain appropriate encryption standards |

---

## Recommended immediate actions (next 90 days)

1. **Commission a crypto-inventory** — automated scan of all TLS endpoints, certificates, and cryptographic library usage across clinical systems. Deliverable: a prioritised list of quantum-vulnerable assets.

2. **Risk-stratify by data retention** — identify which patient datasets have 7+ year retention requirements. These are the HNDL priority targets.

3. **Deploy hybrid TLS on the EHR portal** — the most visible external-facing endpoint. Demonstrates commitment, provides immediate protection for new data, and builds internal capability.

4. **Engage medical device vendors** — begin conversations about PQC roadmaps for infusion pumps, imaging systems, and other embedded devices. These have the longest lead times.

5. **Brief the Board** — quantum risk is now a governance-level topic. The CISO/CIO should present a quantum risk assessment and migration programme proposal within 90 days.

---

## The cost of inaction

| Risk | Consequence |
|------|-------------|
| Patient records harvested today | Retroactive decryption of 7–10 years of clinical data within 10–15 years |
| Regulatory non-compliance | APRA CPG 234 risk management gap; potential EU data transfer restrictions |
| Vendor lock-in | Medical device vendors who don't support PQC will require replacement, not just firmware updates |
| Reputational | A quantum-related data breach in 2033 will be traced to 2025 inaction |

---

*Prepared in the context of the SWERI-Ingham / SWSLHD cryptographic risk assessment engagement.*  
*Technical details and benchmarking data available on request.*
