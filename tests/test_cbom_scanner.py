"""
tests/test_cbom_scanner.py — HealthPQC v2.0
Precision tests for the import-aware AST scanner in tools/cbom_scanner.py.

Covers the three defects fixed in the detection rewrite:
  1. nested calls counted once, not once per AST node
  2. user-defined functions named after algorithms are never flagged
  3. real crypto API usage is still detected, exactly once per scope
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.cbom_scanner import FAMILY, scan_python_file

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_FILE = os.path.join(REPO_ROOT, "examples", "legacy_crypto_demo.py")


def scan_source(tmp_path, source: str, name: str = "sample.py"):
    """Write source to a temp file and scan it. Returns the Finding list."""
    path = tmp_path / name
    path.write_text(source)
    return scan_python_file(str(path))


def algorithms_of(findings):
    return sorted(f.algorithm for f in findings)


# ---------------------------------------------------------------------------
# 1. Nested calls count once
# ---------------------------------------------------------------------------
class TestNestedCallsCountedOnce:
    SOURCE = """
from cryptography.hazmat.primitives.asymmetric import ec

def make_key():
    return ec.generate_private_key(ec.SECP256R1())
"""

    def test_single_finding(self, tmp_path):
        findings = scan_source(tmp_path, self.SOURCE)
        assert len(findings) == 1, f"expected 1 asset, got {algorithms_of(findings)}"

    def test_curve_refines_name_not_adds_component(self, tmp_path):
        findings = scan_source(tmp_path, self.SOURCE)
        assert findings[0].algorithm == "ECDSA-P256"

    def test_repeated_use_in_one_scope_is_one_asset(self, tmp_path):
        source = """
from cryptography.hazmat.primitives.asymmetric import ec

def exchange():
    a = ec.generate_private_key(ec.SECP256R1())
    b = ec.generate_private_key(ec.SECP256R1())
    return a.exchange(ec.ECDH(), b.public_key())
"""
        findings = scan_source(tmp_path, source)
        assert len(findings) == 1
        assert findings[0].algorithm == "ECDH-P256", "agreement usage must win over keygen default"

    def test_separate_scopes_are_separate_assets(self, tmp_path):
        source = """
import hashlib

def one():
    return hashlib.sha1(b"a").hexdigest()

def two():
    return hashlib.sha1(b"b").hexdigest()
"""
        findings = scan_source(tmp_path, source)
        assert len(findings) == 2, "distinct scopes are distinct occurrences"


# ---------------------------------------------------------------------------
# 2. User-defined names must not be flagged
# ---------------------------------------------------------------------------
class TestNoBareIdentifierMatches:
    SOURCE = """
def rsa_helper():
    return 1

def ecdh_p256_exchange():
    return 2

def sha1_digest():
    return 3

class AES:
    def new(self):
        return 4

def main():
    rsa_helper()
    ecdh_p256_exchange()
    sha1_digest()
    AES().new()
"""

    def test_no_findings_at_all(self, tmp_path):
        findings = scan_source(tmp_path, self.SOURCE)
        assert findings == [], f"user-defined names flagged: {algorithms_of(findings)}"

    @pytest.mark.parametrize("name", ["rsa_helper", "ecdh_p256_exchange", "sha1_digest"])
    def test_specific_helper_not_flagged(self, tmp_path, name):
        findings = scan_source(tmp_path, self.SOURCE)
        assert not any(name in f.context for f in findings)

    def test_calling_a_real_api_in_the_same_file_still_works(self, tmp_path):
        """A decoy name must not suppress a genuine finding elsewhere."""
        source = """
import hashlib

def sha1_digest():
    return "not crypto"

def real():
    return hashlib.sha1(b"x").hexdigest()
"""
        findings = scan_source(tmp_path, source)
        assert algorithms_of(findings) == ["SHA-1"]
        assert findings[0].context.startswith("hashlib.sha1")

    def test_type_check_import_is_not_usage(self, tmp_path):
        """Importing `rsa` to run isinstance() is inspection, not cryptographic use."""
        source = """
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

def classify(pub_key):
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        return "EC"
    return "other"
"""
        assert scan_source(tmp_path, source) == []

    def test_unimported_alias_is_not_resolved(self, tmp_path):
        """`ec.generate_private_key` means nothing without the crypto import."""
        source = """
import mymodule as ec

def go():
    return ec.generate_private_key(ec.SECP256R1())
"""
        assert scan_source(tmp_path, source) == []


# ---------------------------------------------------------------------------
# 3. The five demo algorithms, each detected exactly once
# ---------------------------------------------------------------------------
EXPECTED_DEMO_ALGORITHMS = {
    "RSA-2048":   "HIGH",
    "ECDSA-P256": "HIGH",
    "ECDH-P256":  "HIGH",
    "SHA-1":      "HIGH",
    "AES-256":    "MEDIUM",
}


class TestDemoFileDetection:
    @pytest.fixture(scope="class")
    def demo_findings(self):
        assert os.path.exists(DEMO_FILE), f"missing scan target: {DEMO_FILE}"
        # LOW findings (SHA-256 from signature hashing) are informational only.
        return [f for f in scan_python_file(DEMO_FILE) if f.priority != "LOW"]

    @pytest.mark.parametrize("algorithm", sorted(EXPECTED_DEMO_ALGORITHMS))
    def test_algorithm_detected_exactly_once(self, demo_findings, algorithm):
        hits = [f for f in demo_findings if f.algorithm == algorithm]
        assert len(hits) == 1, f"{algorithm}: expected 1 finding, got {len(hits)}"

    def test_no_unexpected_algorithms(self, demo_findings):
        assert algorithms_of(demo_findings) == sorted(EXPECTED_DEMO_ALGORITHMS)

    @pytest.mark.parametrize("algorithm,priority", sorted(EXPECTED_DEMO_ALGORITHMS.items()))
    def test_priority(self, demo_findings, algorithm, priority):
        hit = next(f for f in demo_findings if f.algorithm == algorithm)
        assert hit.priority == priority

    def test_total_count(self, demo_findings):
        assert len(demo_findings) == 5

    def test_every_algorithm_has_a_family(self, demo_findings):
        for f in demo_findings:
            assert f.algorithm in FAMILY, f"{f.algorithm} missing from FAMILY map"

    def test_findings_point_into_the_demo_file(self, demo_findings):
        for f in demo_findings:
            assert f.file.endswith("legacy_crypto_demo.py")
            assert f.line > 0
