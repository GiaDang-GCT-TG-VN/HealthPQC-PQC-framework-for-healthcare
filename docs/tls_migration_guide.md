# TLS Migration Guide — PQC for Healthcare EHR Systems

> Step-by-step guide: migrating an EHR system from classical to hybrid PQC TLS  
> Context: SWERI-Ingham / SWSLHD clinical infrastructure reference  

---

## Overview

This guide covers the complete TLS migration path for a healthcare organisation. It assumes:
- Current state: TLS 1.3 with ECDH-P256 key exchange + ECDSA-P256 certificates
- Target state: Hybrid TLS (X25519 + ML-KEM-768 key exchange) + ML-DSA-65 certificates
- Transition approach: Hybrid first (2025–2030), pure PQC after (2030+)

---

## Phase A — Pre-migration assessment (Weeks 1–4)

### A.1 TLS endpoint inventory

Catalogue all TLS-terminating endpoints:

```bash
# Scan for TLS endpoints in a network range
nmap -p 443,8443,8080 --script ssl-cert 10.0.0.0/24 \
  | grep -E "Subject|Issuer|Not valid|Public Key"

# Check certificate algorithm for a specific host
openssl s_client -connect ehr.hospital.example:443 2>/dev/null \
  | openssl x509 -text -noout \
  | grep -E "Public Key Algorithm|Subject Public Key|Signature Algorithm"
```

### A.2 Certificate inventory (use cert_scanner.py)

```bash
# Run the certificate scanner from this project
python tools/cert_scanner.py --target /etc/ssl/certs --output results/cert_inventory.json
```

### A.3 Priority classification

For each endpoint, classify by:
- **Data sensitivity** (what data flows through this TLS connection?)
- **Session longevity** (are session logs retained? For how long?)
- **Device constraints** (is the client a browser, a server, or an IoT device?)

| Priority | Description | Example |
|----------|-------------|---------|
| P0 — Critical | Long-lived data, high sensitivity | Patient record API (7-year retention) |
| P1 — High | External-facing, moderate retention | EHR web portal |
| P2 — Medium | Internal system-to-system | Database connections |
| P3 — Low | Short-lived, low sensitivity | Log aggregation |

---

## Phase B — Hybrid TLS deployment (Months 1–6)

### B.1 Update TLS configuration

For nginx (example):
```nginx
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;

# Add hybrid key exchange group
ssl_ecdh_curve X25519MLKEM768:x25519:P-256;

# Cipher suites supporting hybrid
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
```

For OpenSSL-based applications:
```python
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.set_ciphers("TLS_AES_256_GCM_SHA384")
# Set hybrid group when OQS-OpenSSL is available
# ctx.set_alpn_protocols(["h2", "http/1.1"])
```

### B.2 Certificate migration strategy

**Dual-certificate approach** (recommended for transition period):
- Issue the same entity both a classical certificate (ECDSA-P256) and a PQC certificate (ML-DSA-65)
- Clients that support PQC certificates use the ML-DSA certificate
- Legacy clients fall back to the classical certificate
- No service disruption

**Certificate hierarchy migration order**:
1. Root CA → ML-DSA-87 (highest priority — longest validity, most impact)
2. Intermediate CA → ML-DSA-65
3. Leaf certificates → ML-DSA-65 (coordinate with natural renewal cycle)

### B.3 Verify hybrid is working

```bash
# Check that hybrid key exchange was negotiated
openssl s_client -connect ehr.hospital.example:443 \
  -groups X25519MLKEM768 -tls1_3 2>&1 \
  | grep -E "Server Temp Key|groups|key exchange"

# Expected output (when hybrid is active):
# Server Temp Key: X25519MLKEM768, ...
```

---

## Phase C — Full PQC migration (Post-2030)

### C.1 Drop classical fallback

Once ecosystem support is confirmed (>95% of clients support PQC natively):
- Remove X25519 from hybrid — use ML-KEM-768 alone
- Remove ECDSA certificates — use ML-DSA certificates exclusively
- Update all client configurations to require PQC

### C.2 Legacy device strategy

For devices that cannot be updated (legacy infusion pumps, old imaging systems):
- Deploy a PQC-capable TLS proxy/gateway at the network perimeter
- The gateway handles PQC on the external side, classical on the internal side
- The device never needs to change

### C.3 HSM considerations

Hardware Security Modules (HSMs) that don't support PQC require:
- Firmware update (if vendor supports PQC — check Thales, Entrust, nCipher roadmaps)
- Replacement with PQC-capable HSM (if firmware update unavailable)
- Timeline: allow 12–18 months for HSM procurement and validation

---

## Key metrics to track

| Metric | Baseline (Classical) | Target (Hybrid) | Acceptable Delta |
|--------|---------------------|-----------------|-----------------|
| TLS handshake latency P50 | X ms | X + <1ms | <5% |
| TLS handshake latency P99 | X ms | X + <5ms | <10% |
| Certificate file size | ~1KB | ~4KB | Acceptable |
| Key material in handshake | ~96B | ~2.3KB | Acceptable |
| Client compatibility | 100% | >95% (hybrid) | Monitor |

---

## References

- [IETF TLS Hybrid Key Exchange Draft](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [OQS-OpenSSL Fork](https://github.com/open-quantum-safe/openssl)
- [NIST SP 800-52 Rev 3 — TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-3/final)
