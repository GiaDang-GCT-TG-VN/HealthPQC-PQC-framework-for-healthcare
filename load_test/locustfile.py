"""
Locust Load Test — PQC Performance Under Concurrent Healthcare Load
Tests three key exchange scenarios at 100, 500, 1000 concurrent users.

Run:
  locust -f locustfile.py --host http://localhost:8000
  # Open http://localhost:8089 for web UI
  # Or headless:
  locust -f locustfile.py --host http://localhost:8000 \
    --users 1000 --spawn-rate 50 --run-time 60s --headless \
    --csv results/load_test
"""

from locust import HttpUser, task, between, events
import csv
import time


class HealthcareEHRUser(HttpUser):
    """Simulates concurrent EHR portal users during PQC migration."""
    wait_time = between(0.1, 0.5)

    @task(1)
    def classical_session(self):
        """Baseline: current production TLS key exchange."""
        with self.client.get("/classical",
                             name="Classical (X25519)",
                             catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            else:
                r.failure(f"Unexpected status: {r.status_code}")

    @task(1)
    def hybrid_session(self):
        """Target: hybrid PQC key exchange."""
        with self.client.get("/hybrid",
                             name="Hybrid (X25519+ML-KEM-768)",
                             catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            else:
                r.failure(f"Unexpected status: {r.status_code}")

    @task(1)
    def pqc_only_session(self):
        """Future: PQC-only key exchange."""
        with self.client.get("/pqc-only",
                             name="PQC Only (ML-KEM-768)",
                             catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            else:
                r.failure(f"Unexpected status: {r.status_code}")
