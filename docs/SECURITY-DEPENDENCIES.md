# Dependency security and known issues

This document describes known unfixable or accepted dependency vulnerabilities and possible alternatives.

## ecdsa CVE-2024-23342 (Minerva timing attack, no fix)

**Status:** Ignored in `pip-audit` via `--ignore-vuln CVE-2024-23342`. No upstream fix is planned.

**What it is:** A Minerva timing attack on the P-256 curve. Using `ecdsa.SigningKey.sign_digest()` and measuring timing can leak the internal nonce and potentially the private key. Affects ECDSA signing, key generation, and ECDH. **ECDSA signature verification is not affected.**

**Why we have it:** The `ecdsa` package is a transitive dependency of [pycose](https://github.com/TimothyClaeys/pycose). Pycose uses `ecdsa` for deterministic ECDSA (RFC 6979); it uses [cryptography](https://cryptography.io) for other operations.

**Alternatives / mitigations:**

1. **Keep ignoring in CI**  
   Document the risk (as here) and continue with `--ignore-vuln CVE-2024-23342`. The python-ecdsa project [considers side-channel attacks out of scope](https://github.com/tlsfuzzer/python-ecdsa/issues/330); there is no planned fix.

2. **Prefer Ed25519 (EdDSA) where possible**  
   This codebase and pycose support EdDSA (e.g. `EdDSA` / Ed25519), which is not affected by this CVE. When you control key and algorithm choice, prefer Ed25519 for new use.

3. **Limit exposure**  
   If your use case only **verifies** MSO/mdoc signatures (no signing with P-256 in process), the vulnerable code path (signing/keygen) may not be exercised in your deployment. Verification is explicitly unaffected.

4. **Upstream change**  
   Ask or contribute to pycose to use `cryptography` for deterministic ECDSA (ES256/ES384/ES512) instead of `ecdsa`, so the dependency can be dropped once pycose supports it.

5. **Alternative COSE library**  
   Switching to another COSE implementation that does not depend on `ecdsa` would remove the vulnerability from the dependency tree; this would require a larger change in this project.

## cryptography (previously ignored; now resolved)

**Status:** No longer ignored. With current dependency resolution, `pip install` picks `cryptography>=42`, so the previously known cryptography CVEs (e.g. PYSEC-2024-225, CVE-2023-50782, CVE-2024-0727, GHSA-h4gh-qq45-vh27) are addressed by the default resolution.

If you ever see cryptography-related vulns again in CI (e.g. after adding a new dependency that pins `cryptography<42`), options are:

- Prefer upgrading the constraining dependency (e.g. ensure pycose’s transitive deps use versions that allow `cryptography>=42`; [pyhpke](https://pypi.org/project/pyhpke/) 0.6.x already requires `cryptography>=42.0.1,<47`).
- As a last resort, re-add temporary `--ignore-vuln` for the specific cryptography advisories and track the issue until the dependency tree can be updated.
