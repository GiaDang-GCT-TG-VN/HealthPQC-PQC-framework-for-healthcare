"""
tests/test_readme_tables.py — HealthPQC v2.0
The README performance tables are generated from the result CSVs: every number in them is
the CSV's value (tools/readme_perf_tables.py; regenerate with --write).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import readme_perf_tables as t


def test_readme_tables_match_the_csvs():
    text = open(t.README, encoding="utf-8").read()
    assert t.readme_section(text) == t.render(), "run: python tools/readme_perf_tables.py --write"
    assert "| **ML-KEM-768** | FIPS 203 | 0.059 |" in text
    assert "| **Falcon-512** | draft FIPS 206 (FN-DSA) | 3.6225 | 897 | about 655 |" in text
    table = [l for l in t.algorithm_table() if l.startswith("| **")]
    assert [l.split("**")[1] for l in table] == ["ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87", "Falcon-512"]
    assert "ML-KEM-768 keygen measured 0.01–0.059 ms across two single runs; timings below 0.1 ms are noisy." in text
