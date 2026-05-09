# PQC Performance Impact Brief

**Post-Quantum Cryptography — Impact Assessment for Healthcare TLS Endpoints**
Prepared: May 2026 | Platform: Apple Silicon ARM64 (M-series) | Methodology: 1000-iteration benchmark

---

## Executive summary

Hybrid PQC key exchange (X25519 + ML-KEM-768) can be deployed on healthcare TLS endpoints with negligible performance impact. Single-operation P99 latency overhead versus classical X25519 is **+0.162ms** — well within acceptable SLA tolerance for EHR portal operation.

**Surprising finding**: PQC-only ML-KEM-768 (0.045ms) is actually **5× faster** than classical X25519 (0.256ms) on ARM64. Lattice arithmetic is cheaper than elliptic curve operations on Apple Silicon.

**Recommendation**: Proceed with hybrid TLS deployment on all external-facing EHR endpoints. The operational cost is negligible; the HNDL risk reduction is immediate and significant.

---

## Test methodology

| Parameter | Value |
|-----------|-------|
| Test tool | Locust |
| Server | FastAPI (uvicorn, 4 workers) |
| Platform | Apple Silicon ARM64 (macOS) |
| Scenarios | Classical (X25519), PQC-only (ML-KEM-768), Hybrid (X25519+ML-KEM-768+HKDF) |
| Concurrency levels | 100, 500, 1000 users |
| Run duration per scenario | 60 seconds |
| Spawn rate | 10, 50, 100 users/second |

---

## Results

### Single-operation latency (1000 iterations, no concurrency)

| Scenario | Average (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Key Material (B) |
|----------|-------------|----------|----------|----------|-----------------|
| Classical (X25519) | 0.256 | 0.241 | 0.290 | 0.327 | 64 |
| PQC only (ML-KEM-768) | 0.045 | 0.042 | 0.052 | 0.064 | 2272 (1184+1088) |
| Hybrid (X25519+ML-KEM-768) | 0.384 | 0.379 | 0.436 | 0.489 | 2336 |
| **Hybrid overhead vs classical** | **+0.128** | **+0.138** | **+0.146** | **+0.162** | |

### Load test results — 100 concurrent users

| Endpoint | P50 (ms) | P95 (ms) | P99 (ms) | Max (ms) | RPS |
|----------|----------|----------|----------|----------|-----|
| /classical | 2 | 4 | 7 | 35 | 102 |
| /pqc-only | 2 | 4 | 7 | 27 | 101 |
| /hybrid | 2 | 4 | 7 | 36 | 103 |

### Load test results — 500 concurrent users

| Endpoint | P50 (ms) | P95 (ms) | P99 (ms) | Max (ms) | RPS |
|----------|----------|----------|----------|----------|-----|
| /classical | 2 | 3 | 10 | 61 | 511 |
| /pqc-only | 1 | 3 | 10 | 60 | 515 |
| /hybrid | 2 | 4 | 12 | 61 | 508 |

### Load test results — 1000 concurrent users

| Endpoint | P50 (ms) | P95 (ms) | P99 (ms) | Max (ms) | RPS |
|----------|----------|----------|----------|----------|-----|
| /classical | 3 | 26 | 71 | 160 | 1003 |
| /pqc-only | 3 | 26 | 70 | 160 | 1010 |
| /hybrid | 4 | 26 | 71 | 161 | 996 |
| **Delta: hybrid vs classical** | **+1** | **0** | **0** | **+1** | |

**Total requests at 1000 users: 180,423 | Failures: 0 (0%)**

---

## Analysis

### Is the performance overhead acceptable?

**Yes — definitively acceptable.**

Measured results from ARM64 benchmarking:

**Single-operation (no concurrency):**
- P50 overhead: +0.138ms
- P99 overhead: +0.162ms
- Key material increase: +2272B per handshake

**Load test at 1000 concurrent users:**
- Hybrid P99: 71ms vs Classical P99: 71ms — **zero difference**
- 180,423 total requests with **0 failures**
- RPS nearly identical: 996 (hybrid) vs 1003 (classical)

For an EHR portal with an SLA of sub-100ms response time, hybrid PQC is statistically indistinguishable from classical at production load.

**Key insight**: ML-KEM-768 lattice operations are faster than X25519 elliptic curve operations on Apple Silicon. At scale, the hybrid overhead disappears entirely into network and HTTP processing variance.

### Key material size impact

The largest operational change is not latency but **key material size in TLS handshakes**:

| Component | Classical | Hybrid PQC | Delta |
|-----------|-----------|-----------|-------|
| Client key share | 32B (X25519) | 32+1184B = 1216B | +1184B |
| Server key share | 32B | 32+1088B = 1120B | +1088B |
| Certificate (ECDSA→ML-DSA-65) | ~1KB | ~4KB | +3KB |
| **Total handshake overhead** | ~2KB | ~8KB | **+6KB** |

At 1,000 concurrent connections, this is approximately 6MB of additional network data per connection cycle — negligible for a 1Gbps clinical network.

---

## Clinical deployment recommendation

| System | Current Algorithm | Recommended Migration | Priority | Notes |
|--------|-------------------|----------------------|----------|-------|
| EHR portal (external) | ECDH-P256 + ECDSA cert | Hybrid X25519+ML-KEM-768 + ML-DSA-65 cert | P1 | Deploy next maintenance window |
| Inter-hospital API | ECDH + ECDSA | Hybrid + ML-DSA-65 cert | P1 | Both sides controllable |
| Medical IoT authentication | Various | Falcon-512 | P2 | Coordinate with device vendors |
| Internal database connections | TLS 1.3 + ECDH | Hybrid | P3 | Internal — lower HNDL risk |

---

## Reproduce this benchmark

```bash
# Clone repo and install dependencies
git clone https://github.com/YOUR_USERNAME/pqc-healthcare-framework
cd pqc-healthcare-framework && pip install -r requirements.txt

# Start server
cd load_test && uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4

# Run benchmark (in separate terminal)
locust -f load_test/locustfile.py --host http://localhost:8000 \
  --users 1000 --spawn-rate 100 --run-time 60s --headless \
  --csv results/load_1000
```

Results will be in `results/load_1000_stats.csv` and `results/load_1000_stats_history.csv`.
