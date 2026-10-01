# Why Healthcare Needs Post-Quantum Cryptography

> Generic context document. No institution-specific, patient-specific, or deployment-specific
> information is included. Figures below are drawn from published standards and public
> regulatory guidance, not from any operational environment.

---

## The short version

Healthcare is one of the sectors where the quantum threat to public-key cryptography is **not**
a 2035 problem. It is a *today* problem, because the data being transmitted today has a
confidentiality lifetime that extends well past the point at which a cryptographically relevant
quantum computer is expected to exist.

Three properties make healthcare unusually exposed:

1. **Very long data retention** — clinical records outlive the cryptography protecting them.
2. **High-value, re-identifiable data** — genomic and diagnostic data cannot be reissued.
3. **Large, heterogeneous, long-lived estates** — EHR platforms, PKI, and medical IoT devices
   with 10–15 year service lives, often with limited crypto-agility.

---

## 1. Retention periods outlive cryptographic lifetimes

Medical record retention obligations are measured in decades, not years. Common requirements
across jurisdictions include:

| Data class | Typical minimum retention |
|------------|---------------------------|
| Adult clinical records | 7–10 years after last contact |
| Paediatric records | Until the patient reaches 25–28 years of age |
| Genomic / hereditary data | Indefinite in practice — relevant to relatives |
| Imaging and diagnostics | 7–15 years |
| Research datasets under ethics approval | Per approval, often 15+ years |

A record created now and retained for 25 years must remain confidential until roughly 2050.
Any RSA- or elliptic-curve-protected channel carrying that record is only as durable as the
assumption that factoring and discrete-log stay hard for that entire window.

---

## 2. Harvest Now, Decrypt Later (HNDL)

HNDL — also called store-now-decrypt-later or SNDL — is the attack that makes retention the
central issue:

1. An adversary captures encrypted traffic **today**, without being able to read it.
2. The ciphertext is archived cheaply and indefinitely.
3. When a cryptographically relevant quantum computer becomes available, Shor's algorithm
   breaks the recorded key exchange and the archived traffic is decrypted retroactively.

The important consequence is the **timing**: migrating to post-quantum key exchange after a
quantum computer exists protects nothing that was already captured. Protection has to be in
place *before* the data crosses the wire.

A useful way to frame the urgency is Mosca's inequality — if the time needed to migrate plus
the required confidentiality lifetime of the data exceeds the time until a quantum computer
arrives, data is already being lost. For healthcare, the confidentiality lifetime term is large
enough that the inequality is satisfied under almost any plausible estimate.

Note that HNDL applies asymmetrically:

- **Key exchange and encryption** (ECDH, RSA-KEM) are retroactively vulnerable — capture now,
  break later. Migration is urgent.
- **Signatures and authentication** (RSA, ECDSA) are not retroactively vulnerable in the same
  way; an adversary cannot usefully forge a signature on a transaction that already completed.
  Migration still matters, but the deadline is driven by the quantum computer's arrival rather
  than by data retention.

---

## 3. Where the exposure actually sits

### EHR and clinical application traffic

Electronic health record systems expose TLS endpoints to clinicians, patient portals,
third-party integrations, and HL7/FHIR interfaces. Every one of those handshakes negotiates a
classical key exchange that is HNDL-exposed. These are also the highest-volume, highest-value
flows, which makes them the natural first target for hybrid key exchange — hybrid
(X25519 + ML-KEM-768) is backward compatible and fails safe to classical security if the
post-quantum component is ever broken.

### PKI and certificate infrastructure

Healthcare organisations typically run internal certificate authorities issuing certificates to
clinical workstations, devices, service endpoints, and clinical software signing pipelines.
Two distinct problems:

- **Root and intermediate CAs** are signed with RSA or ECDSA and have validity periods of
  10–20 years. A root issued today may still be in service after a quantum computer exists,
  so its signature algorithm matters now.
- **Code signing for clinical software** requires signatures that remain verifiable and
  unforgeable for the device's entire service life. Stateless hash-based signatures (SLH-DSA)
  or ML-DSA are the relevant replacements, with the tradeoff being signature size.

Certificate estates are also the hardest part of a migration to plan, because the inventory is
usually incomplete. A crypto-inventory / CBOM pass is the prerequisite for everything else.

### Medical IoT and connected devices

Infusion pumps, monitors, imaging equipment, and wearables are the worst case:

- **Long service lives** — 10–15 years is normal, and replacement is capital-budget constrained.
- **Constrained compute and bandwidth** — post-quantum keys and signatures are larger than
  their classical equivalents, and some devices cannot absorb that in firmware or on the link.
- **Regulatory friction** — changing cryptography on a certified medical device may require
  re-certification, which lengthens any migration timeline considerably.
- **Limited or absent crypto-agility** — algorithms are frequently hard-coded, so the only
  migration path is firmware replacement or device replacement.

This is the part of the estate where migration planning has to start earliest, even though
the EHR traffic is where the HNDL exposure is largest.

---

## 4. What the standards landscape requires

The algorithms are no longer a research question. NIST finalised the core set:

| Standard | Algorithm | Role |
|----------|-----------|------|
| FIPS 203 | ML-KEM (Kyber) | Key encapsulation — replaces ECDH/RSA key exchange |
| FIPS 204 | ML-DSA (Dilithium) | Digital signatures — general purpose |
| FIPS 205 | SLH-DSA (SPHINCS+) | Hash-based signatures — conservative, firmware/root signing |
| FIPS 206 (draft) | FN-DSA (Falcon) | Compact signatures — constrained devices |

Public guidance converges on a similar shape: build a cryptographic inventory, prioritise by
data confidentiality lifetime, deploy hybrid key exchange on high-value traffic first, and
treat algorithm choice as configuration rather than code. Regulatory deadlines cluster around
2030 for deprecation of classical public-key cryptography and 2035 for full migration — but
as the HNDL argument above shows, those deadlines govern *compliance*, not *exposure*.

---

## 5. Implications for system design

The practical conclusion that motivates this repository:

- **Crypto-agility is the deliverable**, not any single algorithm. Systems should be able to
  change KEM and signature algorithms through configuration, because the parameter sets will
  change again.
- **Measure before deciding.** Post-quantum algorithms have different cost profiles —
  ML-KEM is fast with moderate key sizes; Falcon has slow keygen but compact signatures;
  SLH-DSA is conservative but large. The right choice is use-case dependent, which requires
  real benchmark data per device class.
- **Inventory first.** You cannot migrate cryptography you have not found. Static analysis of
  application code plus certificate scanning gives the starting map.
- **Hybrid first, PQC-only later.** Hybrid key exchange is the low-risk move: it is backward
  compatible and retains classical security guarantees alongside post-quantum ones.

---

## References

- NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard
- NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard
- NIST SP 1800-38 — Migration to Post-Quantum Cryptography
- NSA CNSA 2.0 — Commercial National Security Algorithm Suite
- ENISA — Post-Quantum Cryptography: Integration Study
- M. Mosca, "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?"
