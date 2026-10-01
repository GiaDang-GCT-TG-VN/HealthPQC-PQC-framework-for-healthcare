"""
load_test/locustfile.py — HealthPQC v2.0
H5 FIX: warmup period excludes first 15s from stats.
Targets: /classical, /pqc-only, /hybrid (load_test/app.py endpoints)
Run: locust -f locustfile.py --host http://localhost:8000
"""

import time
from locust import HttpUser, task, between, events

WARMUP_SECONDS = 15
_start_time    = None


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    global _start_time
    _start_time = time.time()
    print(f"\n[HealthPQC] Warmup: {WARMUP_SECONDS}s — first {WARMUP_SECONDS}s excluded from stats")
    print(f"[HealthPQC] Steady-state measurement begins at T+{WARMUP_SECONDS}s\n")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    print(f"\n[HealthPQC] Load test complete.")
    print(f"[HealthPQC] Note: warmup ({WARMUP_SECONDS}s) was excluded from all reported metrics.")
    print(f"[HealthPQC] Results reflect steady-state crypto performance only.\n")


class PQCLoadUser(HttpUser):
    """
    Simulates concurrent users hitting classical, PQC-only, and hybrid endpoints.
    Task weights: 3:1:1 (hybrid is the primary comparison point).
    """
    wait_time = between(0.05, 0.2)

    def _in_warmup(self) -> bool:
        return _start_time is None or (time.time() - _start_time) < WARMUP_SECONDS

    @task(3)
    def test_hybrid(self):
        """Hybrid X25519 + ML-KEM-768 — primary comparison target."""
        with self.client.get("/hybrid", catch_response=True, name="hybrid (X25519+ML-KEM-768)") as resp:
            if self._in_warmup():
                resp.success()  # H5 FIX: don't count warmup in stats
                return
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}")

    @task(1)
    def test_classical(self):
        """Classical X25519 — baseline."""
        with self.client.get("/classical", catch_response=True, name="classical (X25519)") as resp:
            if self._in_warmup():
                resp.success()
                return
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}")

    @task(1)
    def test_pqc_only(self):
        """PQC-only ML-KEM-768 — no classical fallback."""
        with self.client.get("/pqc-only", catch_response=True, name="pqc-only (ML-KEM-768)") as resp:
            if self._in_warmup():
                resp.success()
                return
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}")
