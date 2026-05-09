# Interview Preparation Guide — EY Quantum Associate

> Complete Q&A per phase, technical depth expectations, and talking points  
> Interviewer: Kartheek Solipuram (EY Global Innovation Quantum Leader)  

---

## Before the interview — what to bring

| Item | Format | Used when |
|------|--------|-----------|
| Printed benchmark table (from Phase 1) | 1 page | "Show me algorithm performance data" |
| Printed algorithm index (condensed) | 1 page | "Which algorithm would you choose for X?" |
| SWERI engagement summary | 1 page | Opening — hand over when SWERI comes up |
| GitHub repo open on laptop | Browser | "Do you have any code to show?" |
| IEEE paper abstracts (3) | Printed | Credibility anchor — available if asked |
| Benchmark results CSV open | Spreadsheet | "Show me the actual numbers" |

---

## Category 1 — Strategic and risk framing

### Q: "Walk me through what harvest-now-decrypt-later means and why a healthcare organisation should care today."

**Answer structure:**

The threat is asymmetric in time. Adversaries intercept and store encrypted TLS traffic today — patient records, research data, inter-hospital communications. The data is useless to them now because they can't break the encryption. But when a cryptographically relevant quantum computer exists — likely in the 2030–2035 timeframe — they decrypt everything retroactively.

For healthcare specifically: patient records with 7–10 year retention requirements, pathology archives, genomic research data. Any data that is sensitive today and will remain sensitive in 10 years is already at risk of retroactive exposure.

The key phrase that lands with executives: *"The attack has already started. The decryption hasn't."*

**Follow-up they'll ask**: "How do you quantify that risk for a CISO who says quantum computers are still 10 years away?"

**Answer**: You don't fight the timeline debate. You reframe it: migration takes 3–7 years. If they start when quantum computers arrive, they're already too late. The question isn't "when will quantum computers exist?" — it's "how long does it take us to migrate?" That answer is always longer than they think.

---

### Q: "A CISO at a health district comes to you. 50,000 TLS endpoints, 200 applications, PKI certificates on different expiry cycles. Where do you start?"

**Answer — 4-step framework:**

**Step 1: Crypto-inventory.** You cannot migrate what you cannot see. First deliverable is a complete cryptographic asset map — every endpoint, every certificate, every algorithm. I built an automated CBOM scanner (`tools/cbom_scanner.py`) that does exactly this — outputs structured JSON with vulnerability status and migration priority.

**Step 2: Risk stratification.** Not all data is equal. Classify by data sensitivity × retention period. A TLS session for a public web page — low retention, low priority. Patient genomic data retained 10 years — critical priority. I implemented this in the certificate scanner — long-lived certificates with quantum-vulnerable algorithms are automatically flagged as CRITICAL.

**Step 3: Hybrid deployment on P0 systems.** Deploy hybrid key exchange (X25519 + ML-KEM-768) on the highest-risk TLS endpoints immediately. This protects new data from HNDL without breaking anything — fully backward compatible.

**Step 4: Full migration through priority tiers.** Work through tiers as certificate renewal cycles allow. Align PQC migration with natural certificate expiry — no forced emergency re-issuance unless a system is P0 critical.

---

### Q: "Explain crypto-agility to me like I'm presenting it to a Board."

**Answer:**

Crypto-agility means your systems can swap cryptographic algorithms the way you swap a software dependency — through configuration, not a rebuild. It's infrastructure-level flexibility that lets you respond to any cryptographic change in days, not years.

The historical failure mode: RSA is hardcoded into 40 different systems at the protocol level. When RSA needs to change, you have 40 separate engineering projects. That's years of work.

The crypto-agile model: algorithms are parameters, not hardcoded assumptions. When NIST says "migrate from ML-KEM-768 to ML-KEM-1024," your team changes one config file per system — not 40 codebases. I demonstrated this in the `tools/crypto_agility_engine.py` — the algorithm is a parameter in `config/crypto_config.yaml`. Swapping from ML-DSA-65 to Falcon-512 for IoT is one line change.

Board-level framing: *"It's insurance. We pay a small engineering cost now to build flexibility in, so any future cryptographic event — quantum-driven or a discovered vulnerability — doesn't require emergency system rebuilds."*

---

## Category 2 — Algorithm knowledge

### Q: "Why ML-KEM over Classic McEliece? Both are NIST-standardised."

**Answer:**

ML-KEM-768 has a 1,184-byte public key and 1,088-byte ciphertext. Classic McEliece has public keys in the hundreds of kilobytes to megabytes. That difference determines whether the algorithm is TLS-compatible.

A TLS handshake has practical size constraints — very large key shares cause fragmentation and latency issues. ML-KEM fits cleanly. Classic McEliece does not.

Classic McEliece's advantage is mathematical conservatism — it's based on error-correcting codes, a completely different mathematical family from lattice problems. 40+ years of cryptanalysis with no quantum speedup found. If you want maximum mathematical diversity as a hedge, Classic McEliece is the choice — but only for offline, archival contexts where key size is irrelevant.

**Decision rule**: ML-KEM for anything requiring network efficiency. Classic McEliece for long-term archival key wrapping or offline certificate authorities.

---

### Q: "Why is Falcon specifically better for IoT than ML-DSA?"

**Answer — use the numbers:**

Falcon-512 signature: approximately 666 bytes.  
ML-DSA-65 signature: approximately 3,309 bytes.

For a medical infusion pump sending an authentication packet over a low-bandwidth channel, that difference is the difference between feasible and impossible. Packet budgets for constrained IoT devices are often under 1KB. Falcon fits. ML-DSA doesn't.

Both are quantum-safe signature schemes. Both prove identity and integrity. But Falcon's NTRU lattice structure generates shorter signatures. The trade-off: Falcon's key generation requires complex floating-point arithmetic — harder to implement correctly and harder to make side-channel resistant. ML-DSA is simpler to audit.

**Rule**: Falcon-512 for IoT and embedded devices. ML-DSA-65 for servers and applications where implementation simplicity matters more than signature size.

---

### Q: "What is the difference between a KEM and a digital signature?"

**Answer — use the QHE bridge:**

A KEM (Key Encapsulation Mechanism) establishes a shared secret between two parties over an untrusted channel. Neither party transmits the secret — they both arrive at it independently. This is what ML-KEM does — it replaces ECDH in TLS key exchange.

A digital signature proves that a message came from a specific party and wasn't modified. The signer uses their private key to produce a signature; anyone with the public key can verify it. This is what ML-DSA and Falcon do — they replace ECDSA in certificates and code signing.

**They solve different problems and are never interchangeable.**

In TLS 1.3, you need both simultaneously: the KEM establishes the session key (what you say is private), the certificate signature authenticates the server (who you're talking to is verified).

**My QHE bridge**: In my QHE architecture, the QOTP encryption layer is the KEM equivalent — it establishes a shared quantum key. A signature layer would sit outside it to authenticate the circuit source. Same architectural separation, quantum implementation.

---

## Category 3 — Live technical tasks

### Task: "Show me your benchmark results. What do the numbers tell you?"

**What to show**: Open `results/healthcare_benchmark.csv` or print the table.

**What to say**:

Looking at keygen times: ML-KEM-768 at 0.031ms is essentially instantaneous — you won't notice it in any real system. The interesting comparison is between signature algorithms.

ML-DSA-65 keygen at 0.089ms, Falcon-512 at 9.2ms — Falcon's keygen is 100× slower. But Falcon's signature is 0.8ms to produce and 0.3ms to verify, while ML-DSA-65 takes 0.143ms and 0.072ms. So Falcon is slower at keygen but similar at operation time.

The clinical implication: Falcon's slow keygen doesn't matter for medical IoT — you generate the key once at device provisioning. What matters is signature size at authentication time. 666B versus 3,309B — Falcon is the clear IoT choice.

For the EHR portal: ML-KEM-768 for TLS key exchange (fast, standard size), ML-DSA-65 for certificate authentication (implementation simplicity, standard size). The numbers confirm the algorithm selection guidance.

---

### Task: "Build a function that detects whether a TLS certificate is quantum-safe."

**What to open**: `tools/cert_scanner.py` — the `assess_certificate()` function.

**Walk through the logic:**
1. Parse the PEM certificate using `cryptography` library
2. Identify the public key type — RSA, EC, DSA, or unknown
3. Look up the vulnerability database for that key type
4. Calculate days remaining until expiry
5. Escalate priority for long-lived vulnerable certificates — a cert expiring in 2035 with ECDSA is CRITICAL; one expiring next month is MEDIUM
6. Return structured output: algorithm, quantum_safe, priority, replacement, urgency

The key insight is sorting by `days_remaining` in *reverse* when prioritising migration — a certificate expiring in 3 years with RSA-2048 is higher priority than one expiring next month, because it will still be alive when quantum computers arrive.

---

### Task: "Design a PQC migration roadmap for a healthcare organisation."

**Answer — use the 4-phase framework from `docs/tls_migration_guide.md`:**

Phase A (Weeks 1–4): Discovery. Automated crypto-inventory using CBOM scanner + certificate scanner. Deliverable: complete asset map with risk stratification.

Phase B (Months 1–6): Hybrid TLS deployment on P0/P1 systems. Non-breaking — backward compatible. Immediate HNDL protection for new data.

Phase C (Months 6–36): Full migration. Certificate re-issuance, PKI redesign, medical device firmware coordination. Aligned with natural certificate renewal cycles.

Phase D (Months 36–60): Legacy remediation. PQC gateways for non-updatable medical devices. HSM replacement where PQC firmware unavailable.

**Risk flag to raise proactively**: The biggest operational risk in healthcare is legacy medical devices — infusion pumps, imaging systems — that cannot be updated. The mitigation is a PQC gateway at the network perimeter: the device sees classical traffic, the gateway handles the quantum-safe layer externally.

---

## Category 4 — Quantum compute (30% of role)

### Q: "What NISQ algorithm for financial portfolio optimisation? Limitations?"

QAOA — Quantum Approximate Optimisation Algorithm. The problem maps directly: portfolio optimisation is a quadratic unconstrained binary optimisation (QUBO) problem, and QAOA is specifically designed for QUBO on NISQ hardware.

Current limitations: circuit depth is constrained by decoherence. The number of QAOA layers (p) you can run before noise dominates is typically p=3–5 on current IBM hardware. For small portfolios (20–30 assets), QAOA can show advantage. For institutional portfolios (500+ assets), qubit and gate requirements exceed current NISQ capability.

**My angle**: The error suppression pipeline from my PhD — DD + Pauli Twirling + ZNE — directly applies to QAOA circuits on IBM hardware. I validated 3–6× accuracy improvement on ibm_brisbane for QHE circuits. The same pipeline improves QAOA quality at the same circuit depth.

---

### Q: "What is resource estimation and why does it matter for enterprise quantum planning?"

Resource estimation calculates how many qubits, gates, and circuit depth a quantum algorithm requires to solve a problem at useful scale — then compares that to what current hardware provides.

For an enterprise client evaluating quantum investment, this answers: "When will this actually be useful for my problem?" Without it, clients invest based on marketing claims rather than physics.

My practical tool: Qiskit's transpiler at Level 3 optimisation gives gate counts and circuit depth after hardware-specific compilation. You compare this against the decoherence time of the target device to determine if the circuit is executable within noise limits.

**My PhD result**: In my 18-qubit Bell-reuse protocol, I reduced circuit depth by 37% and T-gate count by 50% through selective QHE-CCZ and Bell-pair recycling. That resource estimation methodology — counting gates before and after optimisation — is exactly what you'd apply to any enterprise quantum algorithm to determine readiness.

---

## Category 5 — Thought leadership

### Q: "Why are you the right person for this role?"

**The complete answer:**

EY's quantum program is at a specific inflection point. The thought leadership is established, the IBM alliance is active, and the PQC service line is live. The current challenge is execution — converting client engagements from advisory to delivery.

That requires someone who has already done each step: risk assessment on production systems, algorithm benchmarking, hybrid migration architecture, IBM hardware validation — in contexts with real stakes. My SWERI work at a 500,000-patient health district covers the quantum safety track. Seven years in enterprise SOC operations and network security covers the client delivery track. My PhD in QHE covers the research depth that makes me a long-term asset beyond the PQC migration window.

I don't need a ramp-up period to contribute to either track. And unlike most quantum safety hires who will become less valuable once PQC migration is complete, my QHE research positions me at the frontier of what comes next in enterprise quantum security.

---

### Q: "PQC vs QKD — which should an enterprise deploy?"

PQC: mathematical algorithms that run on classical hardware, drop into existing software, scale to millions of users. ML-KEM, ML-DSA, Falcon — all FIPS-standardised, software-deployable, no new hardware required.

QKD: uses quantum physics (photons) to exchange keys with information-theoretic security. Requires dedicated quantum hardware — fibre or satellite links. Expensive, point-to-point only, limited by photon loss to ~100km without repeaters.

Enterprise recommendation: PQC for 99% of use cases. QKD for specific high-value, point-to-point connections — inter-data-centre links for critical infrastructure, central bank communications.

**The distinction**: QKD solves the key exchange problem with physics. PQC solves it with mathematics. Both are quantum-safe. But PQC integrates into existing TLS and PKI with no hardware changes. QKD requires building a quantum network. For enterprise-scale deployment, PQC is the answer — QKD is a complement for the most sensitive point-to-point links.

---

## Interview sentences — memorise these

| Phase | Sentence |
|-------|----------|
| Phase 1 | "I benchmarked all NIST-standardised PQC algorithms on ARM64 across six clinical use cases. Falcon-512 at 666B versus ML-DSA-65 at 3,309B — that size difference determines whether medical IoT authentication is feasible on a bandwidth-constrained infusion pump." |
| Phase 2 | "I measured hybrid X25519+ML-KEM-768 latency at 1000 iterations. The hybrid adds under 0.05ms average — negligible for an EHR portal. I can demonstrate a live TLS 1.3 connection using ML-DSA-65 for certificate authentication and the hybrid group for key exchange." |
| Phase 3 | "I built a CBOM generator — AST-based, maps every crypto call to quantum vulnerability status and migration priority. Run it against the EHR codebase, pair with the certificate scanner, and you have a complete Phase 1 inventory deliverable in hours, not weeks." |
| Phase 4 | "I load-tested classical versus hybrid PQC at 100/500/1000 concurrent users. P99 latency delta at 1000 users was under 2ms. That's the answer a CTO needs before approving hybrid deployment rollout." |
| Phase 5 | "PQC secures data in transit and at rest — that's the migration problem EY is solving today. QHE secures data while it's being computed on. My PhD puts me at exactly that intersection. APRA CPG 234 is already requiring Australian banks to address quantum risk — that's the local regulatory hook for every financial sector engagement." |
| Overall | "I don't need a ramp-up period. The SWERI engagement means I've already delivered a PQC risk assessment on production clinical infrastructure, and the GitHub repo shows every technical component that engagement required." |
