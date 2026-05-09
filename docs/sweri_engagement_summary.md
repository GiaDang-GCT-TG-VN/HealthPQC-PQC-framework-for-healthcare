# SWERI Engagement Summary — Sanitised

> Professional summary of the SWERI-Ingham cryptographic risk assessment engagement  
> This document is intentionally sanitised — no confidential infrastructure details  
> Verifiable by: Dr. Jim Basilakis, SWERI-Ingham Institute (clinical domain lead)  

---

## Engagement context

**Client**: Major Sydney health district (South Western Sydney Local Health District — SWSLHD)  
**Institution**: SWERI-Ingham Institute for Applied Medical Research  
**Patient population**: 500,000+ patients  
**Duration**: May 2025 – Present  
**Role**: Quantum Safety Researcher (embedded research engagement)  

---

## Engagement scope

This was not a theoretical exercise. The engagement involved direct assessment of production clinical infrastructure and produced deliverables consumed by SWSLHD security teams.

### What was assessed

- RSA and elliptic curve (ECDH/ECDSA) exposure across clinical system categories
- Quantum threat timeline modelling — when does the harvest-now-decrypt-later threat become acute for data with specific retention periods?
- Algorithm benchmarking: ML-KEM (Kyber), ML-DSA (Dilithium), Falcon across device classes present in SWSLHD infrastructure
- Multi-hospital data-sharing protocol design using Quantum Homomorphic Encryption
- Cross-institutional data governance requirements (WSU / SWERI / SWSLHD)

### Deliverables produced

| Deliverable | Consumer | Type |
|-------------|----------|------|
| PQC risk assessment | SWSLHD security team | Technical report |
| PQC migration roadmap | SWSLHD security leadership | Phased action plan |
| Algorithm benchmark results | Security team | Technical data |
| PQC migration runbook | System administrators | Operational document |
| QHE protocol design for multi-hospital data sharing | Research team | Architecture document |
| HREC ethics application (co-designed) | SWERI clinical governance | Governance document |
| Executive security policy recommendations | Non-technical executive leadership | Policy brief |

### Governance outputs

The HREC (Human Research Ethics Committee) ethics application, co-designed with SWERI-Ingham clinical partners, required specifying:
- What patient data would be collected in the research study
- What encryption methods would protect it
- What the threat model was (including quantum threat)
- What governance controls were in place

This is a formal institutional document reviewed by SWERI ethics governance — evidence that the work was real, consequential, and subject to institutional scrutiny.

---

## What cannot be shared (and why)

The following materials are under institutional confidentiality:
- Specific SWSLHD system names, IP ranges, or vendor configurations
- The actual risk assessment findings document (contains infrastructure specifics)
- The HREC application (contains patient data governance details)
- Internal security policy recommendations (contain threat landscape details)

This is standard practice for any security engagement — the same confidentiality applies to Big 4 client work. The methodology, benchmark results, and deliverable structure are accurately documented in this project repo. Dr. Basilakis can verify the engagement scope and nature.

---

## Reference contact

**Dr. Jim Basilakis**  
Principal Supervisor — Western Sydney University  
Clinical Domain Lead — SWERI-Ingham Institute  
Role: Can confirm engagement scope, deliverable types, and technical nature of work  
Context: PhD supervisor and clinical collaborator on the SWERI engagement  

---

## How this maps to the HealthPQC project

Every component of this GitHub repository reflects methodology applied in the SWERI engagement:

| SWERI Activity | HealthPQC Equivalent |
|----------------|---------------------|
| PQC algorithm benchmarking on clinical device classes | `benchmarks/healthcare_benchmark.py` |
| Algorithm selection guidance (Kyber vs Dilithium vs Falcon) | `docs/algorithm_index.md` |
| PQC migration roadmap with phase gates | `docs/tls_migration_guide.md` + `PLAN.md` |
| Risk stratification by data retention | `docs/regulatory_matrix.md` (HNDL section) |
| Executive security policy brief | `docs/pqc_executive_brief.md` |
| QHE protocol design for privacy-preserving data sharing | `docs/pqc_qhe_privacy_stack.md` |

The HealthPQC repo cannot reproduce the confidential SWSLHD-specific findings. It demonstrates the methodology and technical capability that was applied.
