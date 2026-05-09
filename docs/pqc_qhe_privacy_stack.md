# From PQC to QHE — The Complete Privacy Stack for Healthcare

**Technical position paper: how post-quantum cryptography and quantum homomorphic encryption form a complete privacy architecture**

---

## Abstract

Post-quantum cryptography (PQC) addresses the urgent migration problem: replacing RSA, ECDH, and ECDSA with quantum-resistant algorithms before cryptographically relevant quantum computers arrive. Quantum Homomorphic Encryption (QHE) addresses the next frontier: allowing servers to compute on encrypted data without ever decrypting it. These two technologies are not competing approaches — they solve different problems and together form a complete privacy stack. PQC secures data in transit and at rest. QHE secures data *while it is being processed*. This paper outlines the relationship between these fields, the shared mathematical foundations, and the roadmap from PQC migration today to QHE integration in the 5–10 year horizon.

---

## 1. The residual privacy problem after PQC migration

A fully PQC-migrated healthcare system using ML-KEM for TLS key exchange and ML-DSA for certificate authentication still has a fundamental vulnerability: **the server must decrypt data to process it**.

Consider a clinical decision support system:
1. Patient data is encrypted in transit (PQC-secured TLS) ✅
2. Patient data is encrypted at rest (PQC-secured key wrapping) ✅
3. Patient data is **decrypted** on the server to run the diagnostic algorithm ❌ ← residual exposure

The decrypted data exists in server memory during processing. A server compromise, an insider threat, or a rogue cloud provider can access plaintext patient data at this moment — regardless of how strong the transport and storage encryption is.

**PQC solves the channel security problem. It does not solve the computation privacy problem.**

---

## 2. What Quantum Homomorphic Encryption adds

Homomorphic Encryption (HE) — both classical and quantum — allows a server to perform computations on ciphertext and return an encrypted result. The server never sees the plaintext.

```
Classical model (with PQC):
  Patient device → [PQC-encrypted] → Server → DECRYPT → Process → ENCRYPT → Return

QHE model:
  Patient device → [QHE-encrypted] → Server → Process on ciphertext → Return encrypted result
  (Server never sees plaintext — ever)
```

The clinical implication: a hospital can send encrypted genomic data to an external research platform, the platform runs privacy-sensitive analysis algorithms on the encrypted data, and returns encrypted results — without the research platform ever seeing a single patient identifier or genomic sequence.

This is not achievable with PQC alone.

---

## 3. Shared mathematical foundations

Both PQC and QHE are grounded in the same hardness assumptions:

| Foundation | PQC Application | QHE Application |
|------------|----------------|-----------------|
| **Module-LWE** | ML-KEM key structure; ML-DSA commitment scheme | Lattice-based FHE schemes (BFV, CKKS, BGV) |
| **RLWE (Ring-LWE)** | Kyber/Dilithium algebraic structure | Ring-based homomorphic encryption |
| **Lattice problems** | Short vector hardness → encryption security | Circuit evaluation on encrypted integers |
| **Quantum one-time pad** | Not used in PQC | Core of QHE-CCZ protocol (PhD research) |

A researcher or practitioner who understands LWE and RLWE at depth can work across both fields. The PhD research in QHE-CCZ provides precisely this depth — the same mathematical fluency that informs PQC algorithm selection also enables QHE protocol design.

**This is why QHE research is not merely adjacent to PQC work — it is foundational to the next layer of the privacy stack.**

---

## 4. The complete privacy stack

```
┌─────────────────────────────────────────────────────────────┐
│                 COMPLETE HEALTHCARE PRIVACY STACK            │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Computation Privacy (QHE — 5-10 year horizon)     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Server processes encrypted patient data              │    │
│  │ Clinical algorithms run on ciphertext               │    │
│  │ Research platforms see no plaintext                 │    │
│  │ Technology: QHE-CCZ, FHE, CKKS for ML inference    │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Storage Privacy (PQC — now)                        │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Patient records encrypted with ML-KEM-wrapped keys  │    │
│  │ Code signing with ML-DSA-65                        │    │
│  │ Database encryption with AES-256                   │    │
│  │ Technology: ML-KEM, ML-DSA, Falcon-512             │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Transit Privacy (PQC — now, urgent)                │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ TLS 1.3 with hybrid X25519+ML-KEM-768              │    │
│  │ ML-DSA-65 certificates                             │    │
│  │ Falcon-512 for IoT device authentication           │    │
│  │ Technology: OQS-OpenSSL, hybrid TLS                │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

PQC migration (Layers 1 and 2) is urgent, well-defined, and implementable today. QHE integration (Layer 3) is the research frontier — implementable at limited scale now (7–18 qubits on IBM hardware), production-viable as quantum hardware scales to 50–100+ fault-tolerant qubits.

---

## 5. Current QHE research status

The PhD research at Western Sydney University / SWERI-Ingham Institute has produced hardware-validated QHE results directly applicable to healthcare:

| Result | Achievement | Healthcare Application |
|--------|-------------|----------------------|
| 18-qubit Bell-reuse QHE protocol | 96.1% correctness on ibm_brisbane | Transaction ID encryption for patient-diagnosis linkage |
| 3-Layer QHE Architecture | Pluggable EHR, Genomics, QSVM plugins | Domain-specific encrypted inference framework |
| 50% T-gate reduction | 14→7 gates, 37% circuit depth reduction | More complex queries executable within NISQ noise limits |
| DNA Quantum Kernel | 68% quantum advantage over classical | Privacy-preserving genomic analysis on encrypted sequences |
| Error suppression pipeline | 3–6× accuracy improvement (DD+PT+ZNE) | Makes NISQ hardware results production-grade |

**Current limitation**: QHE on NISQ hardware is not yet production-scale for general clinical computation. The research phase (2024–2027) establishes the protocols; production deployment requires fault-tolerant quantum computers (50–100+ logical qubits), anticipated in the 2030–2035 timeframe.

---

## 6. The SafeConsult application — QHE in healthcare context

A concrete application demonstrating the privacy stack in action:

**SafeConsult** is a health consultation application (concept developed during SWERI research) that demonstrates why the complete privacy stack is necessary:

- **Layer 1 (PQC-TLS)**: Conversation between patient and AI assistant is encrypted in transit
- **Layer 2 (PQC storage)**: Patient identity stored encrypted; symptom data stored encrypted
- **Layer 3 (QHE)**: The *linkage* between patient identity and symptom data is encrypted with information-theoretic QHE — the server cannot discover who reported which symptoms, regardless of computing power

Classical FHE handles the computation layer in the deployable version; QHE-CCZ replaces it as quantum hardware scales.

This architecture directly addresses the residual exposure that PQC alone cannot solve: even a fully PQC-migrated server could still connect patient identities to their health data. QHE makes that connection computationally impossible.

---

## 7. Roadmap: PQC today → QHE tomorrow

| Timeframe | Technology | Capability | Action |
|-----------|-----------|-----------|--------|
| 2025–2026 | PQC (ML-KEM, ML-DSA, Falcon) | Secure channels, storage, authentication | **Deploy now — migration urgent** |
| 2025–2027 | Classical FHE (Concrete ML, CKKS) | Encrypted inference on sensitive clinical data | Prototype in high-sensitivity use cases |
| 2026–2028 | NISQ-era QHE (7–18 qubits) | Encrypted transaction linking for small data | Research validation; limited production |
| 2028–2032 | Early fault-tolerant QHE | Broader encrypted computation | Pilot production deployments |
| 2032–2035+ | Production QHE | Full clinical computation on encrypted data | Replace classical FHE where QHE advantage is clear |

---

## 8. Conclusion

The urgency of PQC migration is unambiguous and immediate. The promise of QHE integration is real, staged, and grounded in hardware-validated research. Organisations that build PQC-agile infrastructure today — using crypto-agility patterns that allow algorithm swapping without system redesign — are simultaneously laying the foundation for QHE integration when hardware matures.

The practitioners who understand both fields at depth are rare. Most PQC engineers do not have QHE research experience; most QHE researchers do not have enterprise security engineering backgrounds. The intersection is where the next decade of quantum security will be built.

---

*Based on PhD research at Western Sydney University (QHE-CCZ, 18-qubit Bell-reuse protocol, DNA Quantum Kernel Framework) and applied research at SWERI-Ingham Institute / SWSLHD.*  
*IEEE publications: QCNC 2026 (Accepted), qCCL 2026 (Under Review), QCE 2026 (Pre-print).*
