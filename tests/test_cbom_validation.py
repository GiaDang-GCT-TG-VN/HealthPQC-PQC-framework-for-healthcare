"""
tests/test_cbom_validation.py — HealthPQC v2.0
Pytest suite asserting CycloneDX 1.6 compliance of cbom_emitter output.
Run: pytest tests/test_cbom_validation.py -v
"""

import json
import uuid
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.cbom_emitter import emit_cyclonedx_cbom, finding_to_component, ALGO_META


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
SAMPLE_FINDINGS = [
    {"algorithm": "RSA-2048",    "file": "app/auth.py",    "line": 14, "context": "RSA keygen"},
    {"algorithm": "ECDH",        "file": "app/tls.py",     "line": 38, "context": "ECDH exchange"},
    {"algorithm": "AES-128",     "file": "app/crypto.py",  "line": 72, "context": "AES-128-CBC"},
    {"algorithm": "ML-KEM-768",  "file": "app/pqc.py",     "line": 5,  "context": "ML-KEM encap"},
    {"algorithm": "UNKNOWN-ALGO","file": "app/legacy.py",  "line": 99, "context": "unknown algo"},
]


@pytest.fixture
def cbom():
    return emit_cyclonedx_cbom(SAMPLE_FINDINGS, target="test-suite")


@pytest.fixture
def empty_cbom():
    return emit_cyclonedx_cbom([], target="empty-test")


# ---------------------------------------------------------------------------
# Top-level BOM envelope tests
# ---------------------------------------------------------------------------
class TestBomEnvelope:
    def test_bom_format(self, cbom):
        assert cbom["bomFormat"] == "CycloneDX"

    def test_spec_version(self, cbom):
        assert cbom["specVersion"] == "1.6"

    def test_serial_number_present(self, cbom):
        assert "serialNumber" in cbom

    def test_serial_number_urn_format(self, cbom):
        assert cbom["serialNumber"].startswith("urn:uuid:")

    def test_serial_number_valid_uuid(self, cbom):
        serial = cbom["serialNumber"].replace("urn:uuid:", "")
        uuid.UUID(serial)  # raises ValueError if invalid

    def test_version_is_integer(self, cbom):
        assert cbom["version"] == 1

    def test_components_present(self, cbom):
        assert "components" in cbom

    def test_metadata_present(self, cbom):
        assert "metadata" in cbom

    def test_metadata_has_timestamp(self, cbom):
        assert "timestamp" in cbom["metadata"]

    def test_metadata_has_tools(self, cbom):
        assert "tools" in cbom["metadata"]
        assert len(cbom["metadata"]["tools"]) > 0

    def test_tool_has_name(self, cbom):
        tool = cbom["metadata"]["tools"][0]
        assert "name" in tool
        assert tool["name"] == "HealthPQC"

    def test_empty_cbom_is_valid(self, empty_cbom):
        assert empty_cbom["bomFormat"] == "CycloneDX"
        assert empty_cbom["components"] == []

    def test_each_cbom_has_unique_serial(self):
        cbom1 = emit_cyclonedx_cbom([])
        cbom2 = emit_cyclonedx_cbom([])
        assert cbom1["serialNumber"] != cbom2["serialNumber"]


# ---------------------------------------------------------------------------
# Component structure tests
# ---------------------------------------------------------------------------
class TestComponentStructure:
    def test_component_count(self, cbom):
        assert len(cbom["components"]) == len(SAMPLE_FINDINGS)

    def test_component_type(self, cbom):
        for comp in cbom["components"]:
            assert comp["type"] == "cryptographic-asset"

    def test_component_has_name(self, cbom):
        for comp in cbom["components"]:
            assert "name" in comp
            assert len(comp["name"]) > 0

    def test_component_has_bom_ref(self, cbom):
        for comp in cbom["components"]:
            assert "bom-ref" in comp

    def test_bom_refs_are_unique(self, cbom):
        refs = [c["bom-ref"] for c in cbom["components"]]
        assert len(refs) == len(set(refs))

    def test_crypto_properties_present(self, cbom):
        for comp in cbom["components"]:
            assert "cryptoProperties" in comp

    def test_asset_type_is_algorithm(self, cbom):
        for comp in cbom["components"]:
            assert comp["cryptoProperties"]["assetType"] == "algorithm"

    def test_algorithm_properties_present(self, cbom):
        for comp in cbom["components"]:
            props = comp["cryptoProperties"]["algorithmProperties"]
            assert "primitive" in props
            assert "nistQuantumSecurityLevel" in props
            assert "classicalSecurityLevel" in props


# ---------------------------------------------------------------------------
# C3 FIX: line number must be string
# ---------------------------------------------------------------------------
class TestLineNumberType:
    def test_line_number_is_string(self, cbom):
        """C3 FIX: CycloneDX 1.6 requires line to be a string, not int."""
        for comp in cbom["components"]:
            for occ in comp["evidence"]["occurrences"]:
                assert isinstance(occ["line"], str), (
                    f"line must be str, got {type(occ['line'])} "
                    f"for component {comp['name']}"
                )

    def test_int_line_number_is_converted(self):
        """Verify int line numbers from scanner are cast to str."""
        finding = {"algorithm": "RSA-2048", "file": "test.py", "line": 42, "context": ""}
        comp = finding_to_component(finding)
        line_val = comp["evidence"]["occurrences"][0]["line"]
        assert line_val == "42"
        assert isinstance(line_val, str)

    def test_zero_line_number_is_string(self):
        finding = {"algorithm": "RSA-2048", "file": "test.py", "line": 0, "context": ""}
        comp = finding_to_component(finding)
        assert comp["evidence"]["occurrences"][0]["line"] == "0"


# ---------------------------------------------------------------------------
# Quantum safety level tests
# ---------------------------------------------------------------------------
class TestQuantumSafetyLevels:
    def test_rsa_has_zero_nist_level(self, cbom):
        rsa_comps = [c for c in cbom["components"] if c["name"] == "RSA-2048"]
        assert len(rsa_comps) > 0
        level = rsa_comps[0]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
        assert level == 0, "RSA-2048 must have nistQuantumSecurityLevel=0 (not quantum-safe)"

    def test_ml_kem_has_positive_nist_level(self, cbom):
        kem_comps = [c for c in cbom["components"] if c["name"] == "ML-KEM-768"]
        assert len(kem_comps) > 0
        level = kem_comps[0]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
        assert level > 0, "ML-KEM-768 must have positive nistQuantumSecurityLevel"

    def test_unknown_algorithm_emits_component(self, cbom):
        """Unknown algorithms must still emit a component — never silently drop."""
        unknown = [c for c in cbom["components"] if c["name"] == "UNKNOWN-ALGO"]
        assert len(unknown) == 1

    def test_evidence_has_location(self, cbom):
        for comp in cbom["components"]:
            for occ in comp["evidence"]["occurrences"]:
                assert "location" in occ
                assert len(occ["location"]) > 0
