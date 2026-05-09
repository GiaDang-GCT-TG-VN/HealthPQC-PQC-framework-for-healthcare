# liboqs Installation Guide — Apple Silicon (M1/M2/M3)

> Critical prerequisite for all Phase 1–4 work  
> This file documents exactly why the standard pip install fails and how to fix it  

---

## Before you start — FIPS quick reference

Memorise these three lines. They will be asked in any quantum safety interview:

```
FIPS 203 = ML-KEM (Kyber)   — key exchange, replaces RSA/ECDH in TLS
FIPS 204 = ML-DSA (Dilithium) — signatures, replaces ECDSA in PKI
FIPS 206 = FN-DSA (Falcon)  — compact signatures, replaces ECDSA on IoT devices
```

**Crypto-agility** = the ability to swap cryptographic algorithms without rebuilding the system.  
Example: the `config/crypto_config.yaml` in this project — change one line, algorithm swaps everywhere. That is the exact sentence to use in an EY interview.

Write the FIPS numbers on a sticky note. Pin it to your monitor during installation.

---

## Why Apple Silicon requires building from source

The liboqs Python package on PyPI ships pre-compiled wheels. Those wheels were built for **x86_64 (Intel)**. Apple Silicon (M1/M2/M3) uses **ARM64** — a completely different CPU instruction set.

Running an x86 wheel on ARM64 either:
- Fails immediately with an architecture mismatch error
- Runs through Rosetta 2 emulation, which breaks cryptographic performance and sometimes correctness

The fix: compile liboqs from source, telling cmake to target ARM64 explicitly. The Python bindings then wrap that native ARM64 library.

**Analogy from your QHE work**: this is equivalent to compiling a Qiskit circuit for a specific backend (ibm_brisbane) rather than using a generic transpilation target. Same principle — match the compiled output to the actual hardware.

---

## Pre-installation checklist

Before running any commands, verify these are true:

- [ ] macOS on Apple Silicon (M1/M2/M3) — run `uname -m` → should print `arm64`
- [ ] Homebrew installed — run `brew --version` → should show version number
- [ ] Python virtual environment exists at `~/my_qiskitenv`
- [ ] At least 2GB free disk space (for building liboqs)
- [ ] Internet connection (to clone from GitHub)
- [ ] `sudo` access (needed to install the compiled library)

Run each block below **one at a time**. Verify the expected output before continuing to the next block. If a block fails, do not skip ahead — paste the error output and debug before proceeding.

---

## Block 1 — Prerequisites

```bash
# Check Homebrew is installed
brew --version
# Expected: Homebrew 4.x.x (or similar)

# Install cmake (required to build liboqs C library)
brew install cmake

# Verify cmake installed correctly
cmake --version
# Expected: cmake version 3.x.x

# Also install ninja (faster build tool — optional but recommended)
brew install ninja
```

**If `brew --version` fails**: Homebrew is not installed. Install it first:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Expected Block 1 output:**
```
Homebrew 4.x.x
cmake version 3.x.x
```

---

## Block 2 — Activate your virtual environment

```bash
# Navigate to your Python virtual environment
cd ~/my_qiskitenv

# Activate it
source bin/activate

# Confirm you are in the right environment
which python
# Expected: /Users/giadang/my_qiskitenv/bin/python

# Check Python version
python --version
# Expected: Python 3.13.x

# Confirm pip is from the right env
which pip
# Expected: /Users/giadang/my_qiskitenv/bin/pip
```

**Critical**: every subsequent command must run inside this activated environment. If your terminal prompt shows `(my_qiskitenv)` at the start, you are in the right place.

**Expected Block 2 output:**
```
(my_qiskitenv) /Users/giadang/my_qiskitenv/bin/python
Python 3.13.x
/Users/giadang/my_qiskitenv/bin/pip
```

---

## Block 3 — Build liboqs C library from source

This is the core step. You are compiling the actual C library that implements ML-KEM, ML-DSA, Falcon, and all other OQS algorithms natively for your ARM64 chip.

```bash
# Step 3a: Clone the liboqs source code
# --depth=1 gets only the latest commit — faster, saves ~500MB
git clone --depth=1 https://github.com/open-quantum-safe/liboqs ~/liboqs

# Step 3b: Configure the build
# -DBUILD_SHARED_LIBS=ON  → builds .dylib (required for Python to load at runtime)
# -DCMAKE_BUILD_TYPE=Release → optimised build (not debug)
cmake -S ~/liboqs -B ~/liboqs/build \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES=arm64

# Step 3c: Compile (--parallel 8 uses 8 CPU cores — faster)
cmake --build ~/liboqs/build --parallel 8

# Step 3d: Install to system library path
sudo cmake --build ~/liboqs/build --target install

# Step 3e: Verify the compiled library is present
ls /usr/local/lib/liboqs*
# Expected: /usr/local/lib/liboqs.dylib  (and possibly liboqs.a)
```

**What cmake is doing**: reading the liboqs source code, detecting your system (macOS, ARM64, Apple clang compiler), and generating build instructions tailored to your machine. The `-DCMAKE_OSX_ARCHITECTURES=arm64` flag explicitly forces ARM64 — without it, cmake may default to x86_64.

**This step takes 3–8 minutes** depending on your machine. Normal — the compiler is building every PQC algorithm from scratch.

**Expected Block 3 output (last few lines):**
```
-- Installing: /usr/local/lib/liboqs.dylib
-- Installing: /usr/local/include/oqs/oqs.h
-- Installing: /usr/local/include/oqs/kem_kyber.h
... (many more header files)
```

---

## Block 3 — If it fails (architecture mismatch)

If Block 3 produces an error like:
```
dylib not found
cmake: error: architecture mismatch (arm64 vs x86_64)
ld: warning: ignoring file liboqs.dylib, building for macOS-arm64
```

Add the explicit ARM64 flag:

```bash
# Remove the failed build directory first
rm -rf ~/liboqs/build

# Re-run cmake with explicit architecture flag
cmake -S ~/liboqs -B ~/liboqs/build \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES=arm64

# Then build again
cmake --build ~/liboqs/build --parallel 8
sudo cmake --build ~/liboqs/build --target install
```

If you still see errors after adding `-DCMAKE_OSX_ARCHITECTURES=arm64`, check:
```bash
# What architecture is your cmake targeting?
cmake -S ~/liboqs -B ~/liboqs/build-check \
  -DCMAKE_OSX_ARCHITECTURES=arm64 2>&1 | grep -i arch

# What architecture is your Python?
python -c "import platform; print(platform.machine())"
# Expected: arm64
```

---

## Block 4 — Install Python bindings

The Python bindings are a thin wrapper around the C library you just built. They expose Python functions (`oqs.KeyEncapsulation`, `oqs.Signature`) that call into the native `liboqs.dylib`.

```bash
# Install directly from the official OQS GitHub repo
# (not from PyPI — the PyPI version may be outdated or x86-only)
pip install git+https://github.com/open-quantum-safe/liboqs-python
```

**This step takes 1–3 minutes.** pip is cloning the repo and building the Python extension module.

**Expected output (last few lines):**
```
Successfully built liboqs-python
Installing collected packages: liboqs-python
Successfully installed liboqs-python-x.x.x
```

---

## Block 5 — Verify everything works

```bash
# Run this verification in Python — paste it directly into terminal
python -c "
import oqs

kems = oqs.get_enabled_KEMs()
sigs = oqs.get_enabled_sigs()

print(f'KEMs available: {len(kems)}')
print(f'SIGs available: {len(sigs)}')
print()
print('FIPS 203 check:')
print('  ML-KEM-512  present:', 'ML-KEM-512'  in kems)
print('  ML-KEM-768  present:', 'ML-KEM-768'  in kems)
print('  ML-KEM-1024 present:', 'ML-KEM-1024' in kems)
print()
print('FIPS 204 check:')
print('  ML-DSA-44   present:', 'ML-DSA-44'   in sigs)
print('  ML-DSA-65   present:', 'ML-DSA-65'   in sigs)
print('  ML-DSA-87   present:', 'ML-DSA-87'   in sigs)
print()
print('FIPS 206 check:')
print('  Falcon-512  present:', 'Falcon-512'  in sigs)
print('  Falcon-1024 present:', 'Falcon-1024' in sigs)
print()
print('STATUS: liboqs installed correctly on ARM64')
"
```

**Expected output:**
```
KEMs available: 30+
SIGs available: 30+

FIPS 203 check:
  ML-KEM-512  present: True
  ML-KEM-768  present: True
  ML-KEM-1024 present: True

FIPS 204 check:
  ML-DSA-44   present: True
  ML-DSA-65   present: True
  ML-DSA-87   present: True

FIPS 206 check:
  Falcon-512  present: True
  Falcon-1024 present: True

STATUS: liboqs installed correctly on ARM64
```

If all values show `True`, installation is complete. Proceed to Phase 1.

---

## First algorithm run — confirm the library actually works

After Block 5 succeeds, run this minimal test to confirm not just that the library is present but that algorithms execute correctly:

```python
# Save as: verify_liboqs.py
import oqs
import time

print("=== ML-KEM-768 key exchange test ===")
with oqs.KeyEncapsulation("ML-KEM-768") as server:
    pub = server.generate_keypair()
    print(f"Public key generated: {len(pub)} bytes")

    with oqs.KeyEncapsulation("ML-KEM-768") as client:
        ct, ss_client = client.encap_secret(pub)
        print(f"Ciphertext:          {len(ct)} bytes")
        print(f"Shared secret:       {len(ss_client)} bytes")

    ss_server = server.decap_secret(ct)

assert ss_client == ss_server, "ERROR: Shared secrets do not match!"
print("Shared secrets match: PASS")

print()
print("=== Falcon-512 signature test ===")
message = b"SWERI-SWSLHD-clinical-auth-token"
with oqs.Signature("Falcon-512") as signer:
    pub = signer.generate_keypair()
    sig = signer.sign(message)
    print(f"Signature size: {len(sig)} bytes (vs ML-DSA-65: ~3309 bytes)")

with oqs.Signature("Falcon-512") as verifier:
    valid = verifier.verify(message, sig, pub)

assert valid, "ERROR: Signature verification failed!"
print("Signature verified: PASS")

print()
print("liboqs is fully operational. Ready for Phase 1.")
```

Run it:
```bash
python verify_liboqs.py
```

**Expected output:**
```
=== ML-KEM-768 key exchange test ===
Public key generated: 1184 bytes
Ciphertext:          1088 bytes
Shared secret:       32 bytes
Shared secrets match: PASS

=== Falcon-512 signature test ===
Signature size: ~666 bytes (vs ML-DSA-65: ~3309 bytes)
Signature verified: PASS

liboqs is fully operational. Ready for Phase 1.
```

---

## Troubleshooting reference

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: libliboqs.dylib not found` | Library built but not in system path | Run `sudo cmake --build ~/liboqs/build --target install` again |
| `architecture mismatch (arm64 vs x86_64)` | cmake defaulted to x86 | Add `-DCMAKE_OSX_ARCHITECTURES=arm64` to cmake command |
| `brew: command not found` | Homebrew not installed | Install Homebrew first (see Block 1) |
| `cmake: command not found` | cmake not installed | Run `brew install cmake` |
| `pip install` hangs on git clone | Network issue | Try `pip install git+https://github.com/open-quantum-safe/liboqs-python --timeout 120` |
| `Permission denied` on install step | sudo not used | Always use `sudo cmake --build ~/liboqs/build --target install` |
| `python -c "import oqs"` → no module | Bindings not installed or wrong env | Verify `which python` = venv path; re-run Block 4 |
| `Shared secrets do not match` | Corrupted build | Delete `~/liboqs/build`, rebuild from Block 3 |

---

## What this unlocks

With liboqs installed and verified, you can now run every piece of code in the HealthPQC project:

| File | Requires liboqs | What it does |
|------|----------------|-------------|
| `benchmarks/healthcare_benchmark.py` | ✅ | Benchmark all clinical PQC use cases |
| `benchmarks/full_parameter_sweep.py` | ✅ | Sweep all 30+ available algorithms |
| `tls/hybrid_keyx_benchmark.py` | ✅ | Hybrid X25519+ML-KEM-768 latency |
| `tools/cbom_scanner.py` | ❌ (stdlib only) | Crypto-inventory scan |
| `tools/cert_scanner.py` | ❌ (cryptography lib) | Certificate vulnerability scanner |
| `tools/crypto_agility_engine.py` | ✅ | Algorithm-as-config demo |
| `load_test/app.py` | ✅ | FastAPI load test server |

**Next step**: open `PLAN.md` and follow Phase 1 from the beginning. The first command to run is:

```bash
python benchmarks/healthcare_benchmark.py
```

---

## References

- [Open Quantum Safe — liboqs](https://openquantumsafe.org/liboqs/)
- [liboqs GitHub](https://github.com/open-quantum-safe/liboqs)
- [liboqs-python GitHub](https://github.com/open-quantum-safe/liboqs-python)
- [liboqs getting started](https://openquantumsafe.org/liboqs/getting-started.html)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 206](https://csrc.nist.gov/pubs/fips/206/final)
