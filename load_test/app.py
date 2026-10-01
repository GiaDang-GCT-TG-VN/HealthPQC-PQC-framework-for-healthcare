"""
FastAPI PQC Benchmark Server
Three endpoints simulating different key exchange scenarios.
Context: Measuring production impact of PQC migration on healthcare TLS endpoints
"""

from fastapi import FastAPI
from pydantic import BaseModel
import oqs
import time
import psutil
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

app = FastAPI(
    title="HealthPQC Load Test Server",
    description="Benchmarks classical vs PQC key exchange under concurrent load"
)


class KeyExchangeResult(BaseModel):
    scenario: str
    algorithm: str
    latency_ms: float
    shared_secret_bytes: int
    key_material_bytes: int
    process_memory_mb: float


def get_memory_mb() -> float:
    return round(psutil.Process(os.getpid()).memory_info().rss / 1e6, 1)


@app.get("/", response_model=dict)
def root():
    return {
        "service": "HealthPQC Load Test Server",
        "endpoints": ["/classical", "/pqc-only", "/hybrid"],
        "context": "Healthcare TLS endpoint migration benchmarking"
    }


@app.get("/classical", response_model=KeyExchangeResult)
def classical():
    """X25519 only — current production standard, quantum-vulnerable."""
    t0 = time.perf_counter()
    client = X25519PrivateKey.generate()
    server = X25519PrivateKey.generate()
    shared = client.exchange(server.public_key())
    latency = (time.perf_counter() - t0) * 1000

    return KeyExchangeResult(
        scenario="classical",
        algorithm="X25519",
        latency_ms=round(latency, 4),
        shared_secret_bytes=len(shared),
        key_material_bytes=32 + 32,  # client pub + server pub
        process_memory_mb=get_memory_mb()
    )


@app.get("/pqc-only", response_model=KeyExchangeResult)
def pqc_only():
    """ML-KEM-768 only — fully PQ safe, no classical fallback."""
    t0 = time.perf_counter()
    with oqs.KeyEncapsulation("ML-KEM-768") as server:
        pub = server.generate_keypair()
        with oqs.KeyEncapsulation("ML-KEM-768") as client:
            ct, ss = client.encap_secret(pub)
        recovered = server.decap_secret(ct)
    latency = (time.perf_counter() - t0) * 1000

    return KeyExchangeResult(
        scenario="pqc_only",
        algorithm="ML-KEM-768",
        latency_ms=round(latency, 4),
        shared_secret_bytes=len(ss),
        key_material_bytes=len(pub) + len(ct),  # 1184 + 1088
        process_memory_mb=get_memory_mb()
    )


@app.get("/hybrid", response_model=KeyExchangeResult)
def hybrid():
    """Hybrid X25519 + ML-KEM-768 — NIST/IETF recommended transition approach."""
    t0 = time.perf_counter()

    # Classical component
    client_cl = X25519PrivateKey.generate()
    server_cl = X25519PrivateKey.generate()
    cl_secret = client_cl.exchange(server_cl.public_key())

    # PQC component
    with oqs.KeyEncapsulation("ML-KEM-768") as server_pq:
        pub = server_pq.generate_keypair()
        with oqs.KeyEncapsulation("ML-KEM-768") as client_pq:
            ct, pq_secret = client_pq.encap_secret(pub)

    # Combine via HKDF
    combined = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"hybrid-healthcare-ehr"
    ).derive(cl_secret + pq_secret)

    latency = (time.perf_counter() - t0) * 1000

    return KeyExchangeResult(
        scenario="hybrid",
        algorithm="X25519+ML-KEM-768+HKDF",
        latency_ms=round(latency, 4),
        shared_secret_bytes=len(combined),
        key_material_bytes=32 + len(pub) + len(ct),  # x25519 + mlkem pub + ct
        process_memory_mb=get_memory_mb()
    )
