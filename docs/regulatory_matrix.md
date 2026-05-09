# Regulatory Matrix — PQC Compliance Deadlines

> Reference for client urgency conversations in EY quantum safety engagements  
> Updated: May 2026 | Scope: Global with Australian healthcare focus  

---

## Why this document exists

Clients who understand the technology still don't act without a regulatory driver. This matrix provides the specific deadlines, scope, and requirements that create compliance urgency for each type of organisation EY serves.

**How to use it in a client meeting:**  
Find the client's sector → identify the applicable regulation → state the deadline → frame migration as a compliance programme, not just a security initiative.

---

## Global regulatory landscape

| Regulation | Jurisdiction | Issued By | Applies To | Key Deadline | Core Requirement |
|------------|-------------|-----------|-----------|-------------|-----------------|
| NIST IR 8547 | USA | NIST | All US federal agencies + contractors | 2030 deprecation / 2035 disallowed | Migrate from RSA/ECDH/ECDSA to NIST PQC standards |
| NSA CNSA 2.0 | USA | NSA | National security systems, defence contractors | 2030 | Adopt ML-KEM + ML-DSA; specific product timelines |
| EU PQC Roadmap | European Union | European Commission | All EU member states + regulated sectors | 2026 (roadmaps) / 2030 (migration) | National PQC roadmaps by end 2026; high-risk systems migrated by 2030 |
| DORA (Digital Operational Resilience Act) | European Union | European Parliament | EU financial entities | Ongoing — ICT risk scope | Quantum risk must be addressed in ICT risk management frameworks |
| APRA CPG 234 | Australia | APRA | Banks, insurers, superannuation funds | No fixed deadline — risk-based | Quantum risk now within scope of information security risk management |
| ASD Essential Eight | Australia | ASD/ACSC | Australian government agencies | Ongoing | Patch applications, multi-factor auth — quantum risk guidance evolving |
| UK NCSC PQC Guidance | United Kingdom | NCSC | UK government, critical infrastructure | Guidance issued 2024 — timelines emerging | Begin crypto-inventory and migration planning now |
| ENISA PQC Migration Guide | European Union | ENISA | EU operators of essential services | Reference document | Methodology for crypto-inventory, hybrid deployment, certificate migration |

---

## Detailed breakdown by regulation

### NIST IR 8547 — USA Federal Transition Timeline

**Issued by**: NIST (National Institute of Standards and Technology)  
**Date**: 2024 (initial), updated 2025  
**Scope**: US federal agencies, federal contractors, and any organisation subject to FISMA

**Key requirements**:
- **2030**: Quantum-vulnerable algorithms (RSA, ECDH, ECDSA, DSA) must be deprecated in federal systems
- **2035**: Quantum-vulnerable algorithms disallowed — systems must be fully migrated
- **Now**: NIST encourages organisations to begin transition immediately

**What it means for clients**:
- Any organisation that sells to, contracts with, or connects to US federal agencies must align with this timeline
- Healthcare organisations receiving Medicare/Medicaid funding fall under federal contractor scope
- The 2030 deadline is 4 years away — PQC migrations take 3–7 years — migration must start now

**Client urgency sentence**:  
> "NIST IR 8547 deprecates RSA and ECDH in 2030 and disallows them in 2035. Your PQC migration will take 3–7 years. The start date to meet the 2030 deadline was approximately 2023. The second-best start date is today."

---

### NSA CNSA 2.0 — National Security Algorithm Suite

**Issued by**: National Security Agency (NSA)  
**Date**: September 2022  
**Scope**: National security systems, US defence contractors, suppliers to DoD/IC

**Key requirements**:
- Replace RSA and ECDSA with ML-KEM (FIPS 203) and ML-DSA (FIPS 204) by 2030
- Software and firmware signing: adopt ML-DSA immediately
- Web/cloud services: adopt hybrid PQC key exchange immediately
- Networking equipment: adoption by 2025–2026

**What it means for clients**:
- Any Australian company supplying to US defence or intelligence must comply
- Sets the de facto standard for "quantum-safe" in government procurement globally

---

### European Commission PQC Recommendation (June 2025)

**Issued by**: European Commission + ENISA + NIS Cooperation Group  
**Date**: June 2025  
**Scope**: All EU member states + regulated sectors (banking, healthcare, energy, transport)

**Key requirements**:
- **End of 2026**: All EU member states must establish national PQC transition roadmaps, including awareness campaigns and cryptographic inventories
- **By 2030**: High-risk use cases (healthcare, financial services, critical infrastructure) must be transitioned to PQC
- **By 2035**: All systems transitioned "as practically feasible"

**Healthcare-specific implication**:  
Healthcare is explicitly listed as a "high-risk use case" — EU-operating healthcare organisations have a regulatory obligation to be PQC-migrated by 2030.

**Client urgency sentence**:  
> "The European Commission has mandated that healthcare systems — which it explicitly classifies as high-risk — must be migrated to PQC by 2030. If your organisation operates in any EU market or processes EU patient data, this is a compliance requirement, not a recommendation."

---

### APRA CPG 234 — Australian Prudential Regulation

**Issued by**: APRA (Australian Prudential Regulation Authority)  
**Date**: Original 2019, quantum risk explicitly added to scope in recent guidance  
**Scope**: Australian-regulated entities: banks (ADIs), insurers, superannuation funds

**Key requirements**:
- Information security risk management must address all material threats — quantum computing is now considered a material emerging threat
- Entities must demonstrate they have assessed quantum risk and have a response plan
- No fixed migration deadline, but risk-based expectations apply

**What it means for Australian healthcare clients**:
- Private health insurers regulated by APRA must address quantum risk in their ICT security frameworks
- Hospitals and health networks funded by government bodies face ASD guidance
- The absence of a fixed deadline does not mean no urgency — APRA expects a plan to exist now

**Client urgency sentence**:  
> "APRA now expects regulated entities to have assessed quantum risk as part of their information security posture under CPG 234. The absence of a fixed deadline means APRA can challenge your risk management framework at any time. Not having a PQC assessment and migration plan is a regulatory gap — not just a technology gap."

---

### ENISA PQC Migration Guide — Technical Reference

**Issued by**: ENISA (EU Agency for Cybersecurity)  
**Scope**: Guidance document — operators of essential services, critical infrastructure

**Key methodology elements**:
1. **Crypto-inventory**: Complete mapping of all cryptographic assets (algorithms, key sizes, certificate expiry, data retention periods)
2. **Risk stratification**: Prioritise by data sensitivity × retention period × quantum threat timeline
3. **Hybrid deployment**: Deploy hybrid PQC (classical + quantum-safe) on high-priority systems first
4. **Certificate lifecycle management**: Coordinate migration with natural certificate renewal cycles
5. **Legacy device strategy**: For systems that cannot be updated, deploy PQC-capable gateways at the perimeter

**How this maps to the CBOM tool**:  
The ENISA methodology is exactly what `tools/cbom_scanner.py` implements — automated crypto-inventory as the first step.

---

## Australian healthcare regulatory context

Australia has no direct equivalent to HIPAA, but several frameworks apply:

| Framework | Issued By | Relevance to Healthcare PQC |
|-----------|-----------|----------------------------|
| Privacy Act 1988 (+ Australian Privacy Principles) | OAIC | Health information is sensitive — quantum threat to encryption is a privacy risk |
| My Health Records Act 2012 | Australian Government | My Health Record infrastructure must maintain appropriate encryption — quantum risk in scope |
| ASD Essential Eight | ASD/ACSC | Patch and update management applies to cryptographic libraries |
| ACSC Information Security Manual (ISM) | ASD/ACSC | ISM controls for encryption — quantum-safe algorithm guidance evolving |
| SWSLHD Data Governance Policy | SWSLHD | Clinical data classification and encryption requirements — PQC applies to patient record protection |

**Bottom line for Australian healthcare clients**:  
While there is no Australian equivalent of NIST IR 8547 with a fixed 2030 deadline, the combination of Privacy Act obligations, APRA quantum risk scope (for health insurers), and international standards convergence means PQC migration is a near-term regulatory expectation.

---

## Timeline visualisation

```
2024    2025    2026         2027    2028    2029    2030         2035
  |       |       |            |       |       |       |            |
  ├── NIST FIPS 203/204/205/206 finalised (Aug 2024)
  |       |       |            |       |       |       |            |
  |   ├── NSA CNSA 2.0: networking equipment adoption
  |       |       |            |       |       |       |            |
  |       ├── EU: National PQC roadmaps due (end 2026) ──────────►
  |       |       |            |       |       |       |            |
  |       |   ├── APRA: Quantum risk in scope NOW ────────────────►
  |       |       |            |       |       |       |            |
  |       |       |            |       |   ├── 2030: NIST deprecation ─►
  |       |       |            |       |   ├── 2030: EU high-risk migration
  |       |       |            |       |   ├── 2030: NSA CNSA 2.0 target
  |       |       |            |       |       |       |            |
  |       |       |            |       |       |       |     ├── 2035: NIST disallowed
  |       |       |            |       |       |       |            |
  ◄─────── Migration window: 3-7 years depending on org complexity ──────────────►
  |
  START NOW
```

---

## Harvest-now-decrypt-later threat timeline

| Data Category | Retention Period | Quantum Threat Window | Priority |
|---------------|-----------------|----------------------|----------|
| Current TLS sessions | Hours-days | Low — short-lived | MEDIUM (deploy hybrid now for new data) |
| Patient clinical records | 7–10 years | HIGH — well within quantum timeline | CRITICAL |
| Pathology/imaging archives | 10–20 years | CRITICAL — data already at risk | CRITICAL |
| Research genomic data | Indefinite | CRITICAL | CRITICAL |
| Financial transactions | 7 years (regulatory) | HIGH | HIGH |
| Authentication tokens | Days-months | LOW | LOW |
| Code signing certificates | 1–3 years | MEDIUM | MEDIUM |
| Root CA certificates | 10–20 years | CRITICAL | CRITICAL |

**Key message**: Any data that is sensitive today and will remain sensitive in 10+ years is already being harvested for future decryption. The encryption protecting that data right now needs to be PQC-grade.

---

## References

- [NIST IR 8547](https://csrc.nist.gov/publications/detail/nistir/8547/final)
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [EU PQC Recommendation (June 2025)](https://digital-strategy.ec.europa.eu)
- [APRA CPG 234](https://www.apra.gov.au/cpg-234-information-security)
- [ENISA PQC Migration Guide](https://www.enisa.europa.eu/publications/post-quantum-cryptography)
- [ASD Information Security Manual](https://www.cyber.gov.au/ism)
