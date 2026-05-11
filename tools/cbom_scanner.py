"""
tools/cbom_scanner.py — HealthPQC v2.0
AST-based (Python) + regex (Java/Go/C#/JS) cryptographic inventory scanner.
Emits CycloneDX 1.6 CBOM JSON via cbom_emitter.py.
"""

import ast
import re
import os
import sys
import json
import argparse
from dataclasses import dataclass, field
from typing import List

# --- Inline import guard for cbom_emitter ---
try:
    from tools.cbom_emitter import save_cbom
except ImportError:
    # Allow running directly from repo root
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.cbom_emitter import save_cbom


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    algorithm: str
    file: str
    line: int
    context: str = ""
    scanner: str = "ast"        # "ast" or "regex"
    priority: str = "MEDIUM"    # HIGH / MEDIUM / LOW


# ---------------------------------------------------------------------------
# Algorithm definitions for AST scanner (Python)
# ---------------------------------------------------------------------------
PYTHON_ALGO_PATTERNS = {
    # RSA
    "rsa.generate_private_key":       "RSA",
    "rsa.generate_private_key(":      "RSA",
    "RSA.generate":                   "RSA-2048",
    "RSA.import_key":                 "RSA",
    "rsa.newkeys":                    "RSA",
    "PKCS1_OAEP":                     "RSA",
    # ECDSA / ECDH
    "ec.generate_private_key":        "ECDSA",
    "ec.SECP256R1":                   "ECDSA-P256",
    "ec.SECP384R1":                   "ECDSA-P384",
    "ECDH":                           "ECDH",
    "ECC.generate":                   "ECDSA",
    # DH
    "dh.generate_parameters":         "DH",
    "DHParameters":                   "DH",
    # AES
    "AES.new":                        "AES-128",
    "AES.MODE_CBC":                   "AES-128",
    "AES.MODE_ECB":                   "AES-128",
    "Cipher(algorithms.AES":          "AES-256",
    # Hashes
    "hashlib.sha1":                   "SHA-1",
    "hashlib.md5":                    "SHA-1",     # treat MD5 as SHA-1 risk level
    "hashlib.sha256":                 "SHA-256",
    # PQC (informational — not a vulnerability)
    "ML-KEM":                         "ML-KEM-768",
    "ML-DSA":                         "ML-DSA-65",
    "Kyber":                          "Kyber768",
    "oqs.KeyEncapsulation":           "ML-KEM-768",
    "oqs.Signature":                  "ML-DSA-65",
}

PRIORITY_MAP = {
    "RSA":       "HIGH",
    "RSA-2048":  "HIGH",
    "RSA-4096":  "HIGH",
    "ECDSA":     "HIGH",
    "ECDSA-P256":"HIGH",
    "ECDSA-P384":"HIGH",
    "ECDH":      "HIGH",
    "DH":        "HIGH",
    "AES-128":   "MEDIUM",
    "SHA-1":     "HIGH",
    "SHA-256":   "LOW",
    "ML-KEM-768":"LOW",     # quantum-safe
    "ML-DSA-65": "LOW",
    "Kyber768":  "LOW",
}


# ---------------------------------------------------------------------------
# Multi-language regex patterns (C1 FIX — non-Python files)
# ---------------------------------------------------------------------------
REGEX_PATTERNS = {
    # Java
    r'KeyPairGenerator\.getInstance\("RSA"':        "RSA",
    r'KeyFactory\.getInstance\("RSA"':               "RSA",
    r'Cipher\.getInstance\("RSA':                    "RSA",
    r'KeyPairGenerator\.getInstance\("EC"':          "ECDSA",
    r'KeyAgreement\.getInstance\("ECDH"':            "ECDH",
    r'MessageDigest\.getInstance\("SHA-1"':          "SHA-1",
    r'MessageDigest\.getInstance\("MD5"':            "SHA-1",
    r'"AES/CBC':                                     "AES-128",
    r'"AES/ECB':                                     "AES-128",
    r'DiffieHellman':                                "DH",
    # C# / .NET
    r'new RSACryptoServiceProvider':                 "RSA",
    r'RSA\.Create\(':                                "RSA",
    r'ECDiffieHellmanCng':                           "ECDH",
    r'ECDsaCng':                                     "ECDSA",
    r'new AesCryptoServiceProvider':                 "AES-128",
    r'SHA1CryptoServiceProvider':                    "SHA-1",
    r'MD5CryptoServiceProvider':                     "SHA-1",
    # Go
    r'rsa\.GenerateKey':                             "RSA",
    r'rsa\.EncryptOAEP':                             "RSA",
    r'ecdsa\.GenerateKey':                           "ECDSA",
    r'ecdh\.GenerateKey':                            "ECDH",
    r'sha1\.New\(\)':                                "SHA-1",
    r'des\.NewCipher':                               "SHA-1",    # DES = critical
    r'aes\.NewCipher':                               "AES-128",
    # JavaScript / TypeScript
    r"createDiffieHellman":                          "DH",
    r"generateKeyPair.*'rsa'":                       "RSA",
    r"generateKeyPair.*'ec'":                        "ECDSA",
    r'crypto\.createCipheriv.*"aes-128':             "AES-128",
    r'crypto\.createCipheriv.*"aes-256':             "AES-256",
    r'SHA1|sha1':                                    "SHA-1",
}

SUPPORTED_EXTENSIONS = {
    ".py":   "ast",
    ".java": "regex",
    ".cs":   "regex",
    ".go":   "regex",
    ".js":   "regex",
    ".ts":   "regex",
    ".kt":   "regex",    # Kotlin
    ".rb":   "regex",    # Ruby
    ".cpp":  "regex",
    ".c":    "regex",
}

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "dist", "build", ".tox", ".eggs", "htmlcov",
}


# ---------------------------------------------------------------------------
# AST scanner (Python only)
# ---------------------------------------------------------------------------
class CryptoVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: List[Finding] = []

    def _add(self, algo: str, line: int, ctx: str = ""):
        self.findings.append(Finding(
            algorithm=algo,
            file=self.filepath,
            line=line,
            context=ctx,
            scanner="ast",
            priority=PRIORITY_MAP.get(algo, "MEDIUM"),
        ))

    def visit_Call(self, node: ast.Call):
        call_str = ast.unparse(node) if hasattr(ast, "unparse") else ""
        for pattern, algo in PYTHON_ALGO_PATTERNS.items():
            if pattern.lower() in call_str.lower():
                self._add(algo, node.lineno, call_str[:80])
                break
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name in ("Crypto.PublicKey.RSA", "Cryptodome.PublicKey.RSA"):
                self._add("RSA", node.lineno, f"import {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        if "RSA" in module or "rsa" in module:
            self._add("RSA", node.lineno, f"from {module} import ...")
        elif "EC" in module or "ecdsa" in module.lower():
            self._add("ECDSA", node.lineno, f"from {module} import ...")
        self.generic_visit(node)


def scan_python_file(filepath: str) -> List[Finding]:
    try:
        with open(filepath, "r", errors="replace") as f:
            source = f.read()
        tree = ast.parse(source, filename=filepath)
        visitor = CryptoVisitor(filepath)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError:
        # Fall back to regex for files with syntax errors
        return scan_regex_file(filepath)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Regex scanner (multi-language — C1 FIX)
# ---------------------------------------------------------------------------
def scan_regex_file(filepath: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, "r", errors="replace") as f:
            lines = f.readlines()
        for line_num, line in enumerate(lines, 1):
            for pattern, algo in REGEX_PATTERNS.items():
                if re.search(pattern, line):
                    findings.append(Finding(
                        algorithm=algo,
                        file=filepath,
                        line=line_num,
                        context=line.strip()[:80],
                        scanner="regex",
                        priority=PRIORITY_MAP.get(algo, "MEDIUM"),
                    ))
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# Directory walker
# ---------------------------------------------------------------------------
def scan_directory(target: str, include_pqc_safe: bool = False) -> List[Finding]:
    all_findings: List[Finding] = []
    file_count = 0

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue
            filepath = os.path.join(root, filename)
            file_count += 1
            if SUPPORTED_EXTENSIONS[ext] == "ast":
                findings = scan_python_file(filepath)
            else:
                findings = scan_regex_file(filepath)

            if not include_pqc_safe:
                # Filter out quantum-safe findings unless requested
                findings = [f for f in findings if PRIORITY_MAP.get(f.algorithm, "MEDIUM") != "LOW"]

            all_findings.extend(findings)

    print(f"[HealthPQC] Scanned {file_count} files across {target}")
    return all_findings


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------
def print_summary(findings: List[Finding]):
    by_priority = {"HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        by_priority.get(f.priority, by_priority["MEDIUM"]).append(f)

    print("\n" + "="*64)
    print("  HEALTHPQC v2.0 — CRYPTOGRAPHIC ASSET INVENTORY")
    print("="*64)
    print(f"  Total findings:  {len(findings)}")
    print(f"  HIGH priority:   {len(by_priority['HIGH'])}   ← migrate immediately")
    print(f"  MEDIUM priority: {len(by_priority['MEDIUM'])}")
    print(f"  LOW (safe):      {len(by_priority['LOW'])}")
    print("-"*64)

    for priority in ("HIGH", "MEDIUM"):
        for f in by_priority[priority]:
            scanner_tag = f"[{f.scanner.upper():5s}]"
            print(f"  [{priority:6s}] {scanner_tag} {f.algorithm:14s} {f.file}:{f.line}")
    print("="*64)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="HealthPQC v2.0 — Cryptographic Asset Scanner (CycloneDX 1.6)"
    )
    parser.add_argument("--target", default=".", help="Directory to scan (default: .)")
    parser.add_argument("--output", default="results/cbom_cyclonedx_v1.6.json",
                        help="Output path for CycloneDX CBOM JSON")
    parser.add_argument("--legacy-output", default="results/cbom_legacy.json",
                        help="Also write legacy JSON format for backward compat")
    parser.add_argument("--include-safe", action="store_true",
                        help="Include quantum-safe algorithms in output (informational)")
    args = parser.parse_args()

    print(f"\n[HealthPQC v2.0] Scanning: {os.path.abspath(args.target)}")

    findings = scan_directory(args.target, include_pqc_safe=args.include_safe)
    print_summary(findings)

    # C1 FIX: emit CycloneDX 1.6 (primary output)
    findings_dicts = [
        {"algorithm": f.algorithm, "file": f.file,
         "line": f.line, "context": f.context}
        for f in findings
    ]
    save_cbom(findings_dicts, output_path=args.output,
              target=os.path.basename(os.path.abspath(args.target)))

    # Also write legacy format for backward compatibility
    os.makedirs(os.path.dirname(args.legacy_output)
                if os.path.dirname(args.legacy_output) else ".", exist_ok=True)
    with open(args.legacy_output, "w") as f:
        json.dump([
            {"algorithm": f.algorithm, "file": f.file,
             "line": f.line, "priority": f.priority, "scanner": f.scanner}
            for f in findings
        ], f, indent=2)
    print(f"[HealthPQC v2.0] Legacy JSON → {args.legacy_output}")


if __name__ == "__main__":
    main()
