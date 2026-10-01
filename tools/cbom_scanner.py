"""
tools/cbom_scanner.py — HealthPQC v2.0
Import-aware AST scanner (Python) + regex scanner (Java/Go/C#/JS) for cryptographic assets.
Emits CycloneDX 1.6 CBOM JSON via cbom_emitter.py.

Detection model
---------------
A Python call is only reported when it resolves to a known crypto module through the
file's own import statements. `hashlib.sha1(x)` is reported; a user-defined
`sha1_helper()` or `ecdh_p256_exchange()` is not, because neither resolves into
`hashlib`, `cryptography`, `Crypto`/`Cryptodome`, `ssl` or `oqs`.

Findings are deduplicated per (file, enclosing scope, algorithm family), so one
cryptographic asset used across several lines of a function is one asset. Nested
expressions such as `ec.generate_private_key(ec.SECP256R1())` are a single finding;
the curve refines the name rather than adding a second component.
"""

import ast
import re
import os
import sys
import json
import argparse
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

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
# Algorithm families — the dedup key. One asset per family per scope.
# ---------------------------------------------------------------------------
FAMILY = {
    "RSA": "RSA", "RSA-1024": "RSA", "RSA-2048": "RSA", "RSA-4096": "RSA",
    "ECDSA": "EC", "ECDSA-P256": "EC", "ECDSA-P384": "EC", "ECDSA-P521": "EC",
    "ECDH": "EC", "ECDH-P256": "EC", "ECDH-P384": "EC", "ECDH-P521": "EC",
    "DH": "DH",
    "AES-128": "AES", "AES-192": "AES", "AES-256": "AES",
    "3DES": "3DES",
    "SHA-1": "SHA-1", "MD5": "MD5", "SHA-256": "SHA-2", "SHA-384": "SHA-2", "SHA-512": "SHA-2",
    "ML-KEM-768": "PQC", "ML-DSA-65": "PQC", "Kyber768": "PQC",
}

PRIORITY_MAP = {
    "RSA": "HIGH", "RSA-1024": "HIGH", "RSA-2048": "HIGH", "RSA-4096": "HIGH",
    "ECDSA": "HIGH", "ECDSA-P256": "HIGH", "ECDSA-P384": "HIGH", "ECDSA-P521": "HIGH",
    "ECDH": "HIGH", "ECDH-P256": "HIGH", "ECDH-P384": "HIGH", "ECDH-P521": "HIGH",
    "DH": "HIGH",
    "SHA-1": "HIGH", "MD5": "HIGH", "3DES": "HIGH",
    "AES-128": "MEDIUM", "AES-192": "MEDIUM", "AES-256": "MEDIUM",
    "SHA-256": "LOW", "SHA-384": "LOW", "SHA-512": "LOW",
    "ML-KEM-768": "LOW", "ML-DSA-65": "LOW", "Kyber768": "LOW",   # quantum-safe
}

# Only calls resolving into these top-level packages are considered crypto API usage.
CRYPTO_ROOTS = ("cryptography", "hashlib", "Crypto", "Cryptodome", "ssl", "oqs")

# Canonical dotted path -> algorithm name (or a marker handled in _resolve_call).
CALL_RULES: Dict[str, str] = {
    # --- pyca/cryptography -------------------------------------------------
    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": "@RSA",
    "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key":  "@EC_KEY",
    "cryptography.hazmat.primitives.asymmetric.ec.derive_private_key":    "@EC_KEY",
    "cryptography.hazmat.primitives.asymmetric.ec.ECDSA":                 "@EC_SIGN",
    "cryptography.hazmat.primitives.asymmetric.ec.ECDH":                  "@EC_AGREE",
    "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters":   "DH",
    "cryptography.hazmat.primitives.ciphers.algorithms.AES":              "AES-128",
    "cryptography.hazmat.primitives.ciphers.algorithms.AES128":           "AES-128",
    "cryptography.hazmat.primitives.ciphers.algorithms.AES256":           "AES-256",
    "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES":        "3DES",
    "cryptography.hazmat.primitives.hashes.SHA1":                         "SHA-1",
    "cryptography.hazmat.primitives.hashes.MD5":                          "MD5",
    "cryptography.hazmat.primitives.hashes.SHA256":                       "SHA-256",
    "cryptography.hazmat.primitives.hashes.SHA384":                       "SHA-384",
    "cryptography.hazmat.primitives.hashes.SHA512":                       "SHA-512",
    # --- hashlib -----------------------------------------------------------
    "hashlib.sha1":   "SHA-1",
    "hashlib.md5":    "MD5",
    "hashlib.sha256": "SHA-256",
    "hashlib.sha384": "SHA-384",
    "hashlib.sha512": "SHA-512",
    # --- PyCryptodome / PyCrypto ------------------------------------------
    "Crypto.PublicKey.RSA.generate":      "@RSA",
    "Crypto.PublicKey.RSA.import_key":    "RSA",
    "Crypto.PublicKey.ECC.generate":      "ECDSA",
    "Crypto.Cipher.AES.new":              "AES-128",
    "Crypto.Cipher.DES3.new":             "3DES",
    "Crypto.Hash.SHA1.new":               "SHA-1",
    "Crypto.Hash.MD5.new":                "MD5",
    "Crypto.Cipher.PKCS1_OAEP.new":       "RSA",
    # --- liboqs (quantum-safe, informational) ------------------------------
    "oqs.KeyEncapsulation": "ML-KEM-768",
    "oqs.Signature":        "ML-DSA-65",
}
# Cryptodome mirrors the Crypto namespace exactly.
CALL_RULES.update({
    k.replace("Crypto.", "Cryptodome.", 1): v
    for k, v in CALL_RULES.items() if k.startswith("Crypto.")
})

# Imports that name an algorithm outright, i.e. importing the module *is* the usage.
# Used only as a fallback when no call site for the same family was found in the file.
# pyca/cryptography namespaces (`asymmetric.rsa`, `asymmetric.ec`) are deliberately
# excluded: they are routinely imported for type checks such as
# `isinstance(key, rsa.RSAPublicKey)`, which is not cryptographic use.
IMPORT_RULES: Dict[str, str] = {
    "Crypto.PublicKey.RSA":    "RSA",
    "Cryptodome.PublicKey.RSA": "RSA",
    "Crypto.PublicKey.ECC":    "ECDSA",
    "Cryptodome.PublicKey.ECC": "ECDSA",
    "Crypto.Cipher.AES":       "AES-128",
    "Cryptodome.Cipher.AES":   "AES-128",
    "Crypto.Cipher.DES3":      "3DES",
}

CURVE_NAMES = {
    "SECP256R1": "P256", "SECP384R1": "P384", "SECP521R1": "P521",
    "SECP256K1": "P256", "BrainpoolP256R1": "P256", "BrainpoolP384R1": "P384",
}


# ---------------------------------------------------------------------------
# Multi-language regex patterns (non-Python files)
# ---------------------------------------------------------------------------
REGEX_PATTERNS = {
    # Java
    r'KeyPairGenerator\.getInstance\("RSA"':        "RSA",
    r'KeyFactory\.getInstance\("RSA"':               "RSA",
    r'Cipher\.getInstance\("RSA':                    "RSA",
    r'KeyPairGenerator\.getInstance\("EC"':          "ECDSA",
    r'KeyAgreement\.getInstance\("ECDH"':            "ECDH",
    r'MessageDigest\.getInstance\("SHA-1"':          "SHA-1",
    r'MessageDigest\.getInstance\("MD5"':            "MD5",
    r'"AES/CBC':                                     "AES-128",
    r'"AES/ECB':                                     "AES-128",
    r'KeyAgreement\.getInstance\("DiffieHellman"':   "DH",
    # C# / .NET
    r'new RSACryptoServiceProvider':                 "RSA",
    r'RSA\.Create\(':                                "RSA",
    r'ECDiffieHellmanCng':                           "ECDH",
    r'ECDsaCng':                                     "ECDSA",
    r'new AesCryptoServiceProvider':                 "AES-128",
    r'SHA1CryptoServiceProvider':                    "SHA-1",
    r'MD5CryptoServiceProvider':                     "MD5",
    # Go
    r'\brsa\.GenerateKey\(':                         "RSA",
    r'\brsa\.EncryptOAEP\(':                         "RSA",
    r'\becdsa\.GenerateKey\(':                       "ECDSA",
    r'\becdh\.GenerateKey\(':                        "ECDH",
    r'\bsha1\.New\(':                                "SHA-1",
    r'\bmd5\.New\(':                                 "MD5",
    r'\bdes\.NewCipher\(':                           "3DES",
    r'\baes\.NewCipher\(':                           "AES-128",
    # JavaScript / TypeScript
    r"\bcrypto\.createDiffieHellman\(":              "DH",
    r"generateKeyPair(Sync)?\(\s*'rsa'":             "RSA",
    r"generateKeyPair(Sync)?\(\s*'ec'":              "ECDSA",
    r'crypto\.createCipheriv\(\s*["\']aes-128':      "AES-128",
    r'crypto\.createCipheriv\(\s*["\']aes-256':      "AES-256",
    r'crypto\.createHash\(\s*["\']sha1["\']':        "SHA-1",
    r'crypto\.createHash\(\s*["\']md5["\']':         "MD5",
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
    "dist", "build", ".tox", ".eggs", "htmlcov", ".pytest_cache",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _dotted_name(node: ast.AST) -> Optional[str]:
    """Return 'a.b.c' for a Name/Attribute chain, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _specificity(algo: str) -> int:
    """Prefer 'RSA-2048' over 'RSA' and 'ECDSA-P256' over 'ECDSA'."""
    return len(algo)


# ---------------------------------------------------------------------------
# AST scanner (Python)
# ---------------------------------------------------------------------------
class CryptoVisitor(ast.NodeVisitor):
    """Collects crypto signals, resolving every call through the file's imports."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.aliases: Dict[str, str] = {}   # local name -> canonical dotted path
        self.scope: List[str] = ["<module>"]
        # (scope, family) -> dict with best algorithm, line, context
        self.signals: Dict[Tuple[str, str], dict] = {}
        self.ec_usage: Dict[str, str] = {}  # scope -> "sign" | "agree"
        self.import_fallbacks: List[Tuple[str, str, int, str]] = []

    # -- scope tracking ----------------------------------------------------
    @property
    def _scope(self) -> str:
        return ".".join(self.scope)

    def _push(self, node):
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_FunctionDef = _push
    visit_AsyncFunctionDef = _push
    visit_ClassDef = _push

    # -- imports -----------------------------------------------------------
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            canonical = alias.name if alias.asname else alias.name.split(".")[0]
            self.aliases[local] = canonical
            if alias.name in IMPORT_RULES:
                self.import_fallbacks.append(
                    (self._scope, IMPORT_RULES[alias.name], node.lineno, f"import {alias.name}")
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            full = f"{module}.{alias.name}" if module else alias.name
            self.aliases[local] = full
            if full in IMPORT_RULES:
                self.import_fallbacks.append(
                    (self._scope, IMPORT_RULES[full], node.lineno, f"from {module} import {alias.name}")
                )
        self.generic_visit(node)

    # -- calls -------------------------------------------------------------
    def _canonical(self, dotted: str) -> Optional[str]:
        """Expand the leading alias of a dotted call into its imported path."""
        head, _, tail = dotted.partition(".")
        base = self.aliases.get(head)
        if base is None:
            return None
        canonical = f"{base}.{tail}" if tail else base
        if not canonical.split(".")[0] in CRYPTO_ROOTS:
            return None
        return canonical

    def _record(self, algo: str, line: int, context: str):
        family = FAMILY.get(algo, algo)
        key = (self._scope, family)
        existing = self.signals.get(key)
        if existing is None or _specificity(algo) > _specificity(existing["algorithm"]):
            self.signals[key] = {
                "algorithm": algo,
                "line": existing["line"] if existing else line,
                "context": existing["context"] if existing else context,
            }

    def visit_Call(self, node: ast.Call):
        dotted = _dotted_name(node.func)
        if dotted:
            canonical = self._canonical(dotted)
            rule = CALL_RULES.get(canonical) if canonical else None
            if rule:
                self._handle(rule, node, dotted)
        self.generic_visit(node)

    def _handle(self, rule: str, node: ast.Call, dotted: str):
        ctx = f"{dotted}(...)"
        line = node.lineno

        if rule == "@RSA":
            bits = None
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    bits = kw.value.value
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value >= 512:
                    bits = arg.value
            algo = f"RSA-{bits}" if bits in (1024, 2048, 4096) else "RSA"
            self._record(algo, line, ctx)

        elif rule == "@EC_KEY":
            curve = self._curve_of(node)
            self._record(f"ECDSA-{curve}" if curve else "ECDSA", line, ctx)

        elif rule == "@EC_SIGN":
            self.ec_usage[self._scope] = "sign"
            self._record("ECDSA", line, ctx)

        elif rule == "@EC_AGREE":
            self.ec_usage[self._scope] = "agree"
            self._record("ECDH", line, ctx)

        else:
            self._record(rule, line, ctx)

    def _curve_of(self, node: ast.Call) -> Optional[str]:
        """Read the curve out of ec.generate_private_key(ec.SECP256R1())."""
        candidates = list(node.args) + [kw.value for kw in node.keywords]
        for arg in candidates:
            target = arg.func if isinstance(arg, ast.Call) else arg
            name = _dotted_name(target)
            if name:
                leaf = name.split(".")[-1]
                if leaf in CURVE_NAMES:
                    return CURVE_NAMES[leaf]
        return None

    # -- output ------------------------------------------------------------
    def results(self) -> List[Finding]:
        findings: List[Finding] = []
        seen_families = {fam for (_scope, fam) in self.signals}

        for (scope, family), sig in self.signals.items():
            algo = sig["algorithm"]
            # An EC scope that agrees a key is ECDH, not ECDSA, whichever call came first.
            if family == "EC":
                usage = self.ec_usage.get(scope)
                curve = algo.split("-", 1)[1] if "-" in algo else None
                if usage == "agree":
                    algo = f"ECDH-{curve}" if curve else "ECDH"
                elif usage == "sign":
                    algo = f"ECDSA-{curve}" if curve else "ECDSA"
            findings.append(Finding(
                algorithm=algo,
                file=self.filepath,
                line=sig["line"],
                context=sig["context"],
                scanner="ast",
                priority=PRIORITY_MAP.get(algo, "MEDIUM"),
            ))

        # Imports only count when nothing in the file already covers that family.
        for scope, algo, line, ctx in self.import_fallbacks:
            if FAMILY.get(algo, algo) in seen_families:
                continue
            findings.append(Finding(
                algorithm=algo, file=self.filepath, line=line, context=ctx,
                scanner="ast", priority=PRIORITY_MAP.get(algo, "MEDIUM"),
            ))
            seen_families.add(FAMILY.get(algo, algo))

        findings.sort(key=lambda f: (f.line, f.algorithm))
        return findings


def scan_python_file(filepath: str) -> List[Finding]:
    try:
        with open(filepath, "r", errors="replace") as f:
            source = f.read()
        tree = ast.parse(source, filename=filepath)
        visitor = CryptoVisitor(filepath)
        visitor.visit(tree)
        return visitor.results()
    except SyntaxError:
        # Fall back to regex for files with syntax errors
        return scan_regex_file(filepath)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Regex scanner (multi-language)
# ---------------------------------------------------------------------------
def scan_regex_file(filepath: str) -> List[Finding]:
    found: Dict[Tuple[int, str], Finding] = {}
    try:
        with open(filepath, "r", errors="replace") as f:
            lines = f.readlines()
        for line_num, line in enumerate(lines, 1):
            for pattern, algo in REGEX_PATTERNS.items():
                if re.search(pattern, line):
                    key = (line_num, FAMILY.get(algo, algo))
                    if key in found and _specificity(algo) <= _specificity(found[key].algorithm):
                        continue
                    found[key] = Finding(
                        algorithm=algo,
                        file=filepath,
                        line=line_num,
                        context=line.strip()[:80],
                        scanner="regex",
                        priority=PRIORITY_MAP.get(algo, "MEDIUM"),
                    )
    except Exception:
        pass
    return sorted(found.values(), key=lambda f: (f.line, f.algorithm))


# ---------------------------------------------------------------------------
# Directory walker
# ---------------------------------------------------------------------------
def scan_directory(target: str, include_pqc_safe: bool = False) -> List[Finding]:
    all_findings: List[Finding] = []
    file_count = 0

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in sorted(files):
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

    # Emit CycloneDX 1.6 (primary output)
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
