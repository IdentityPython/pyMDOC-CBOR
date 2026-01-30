# X.509 Certificate Chain Verification

## Overview

pyMDOC-CBOR supports comprehensive mDOC verification including:

1. **X.509 Certificate Chain Verification** - Validates that mDOC documents are signed by trusted authorities
2. **Element Hash Verification** - Ensures disclosed data elements match their cryptographic hashes in the MSO

### What is Verified

**Certificate Chain:**
- The Document Signer (DS) certificate is signed by a trusted root certificate
- The DS certificate is within its validity period
- The signature algorithm matches expectations

**Element Hashes:**
- Each disclosed `IssuerSignedItem` matches its SHA-256 hash in the MSO's `valueDigests`
- Hashes are computed on the complete CBOR Tag 24 structure (as per ISO 18013-5 §9.1.2.4)
- All elements in all namespaces are verified

## Usage

### Basic Verification (Signature Only)

```python
# skip in doc examples (requires device_response_bytes from previous context)
from pymdoccbor.mdoc.verifier import MdocCbor

mdoc = MdocCbor()
mdoc.loads(device_response_bytes)

# Verify signatures only (no certificate chain validation, but hash verification enabled)
is_valid = mdoc.verify()
```

**Note:** This mode verifies cryptographic signatures and element hashes, but does not validate the certificate chain. A warning will be logged about certificate chain validation.

### Full Verification (Recommended)

```python
# skip in doc examples (requires device_response_bytes and iaca_cert.pem)
from pymdoccbor.mdoc.verifier import MdocCbor
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load trusted root certificates (IACA certificates)
with open('iaca_cert.pem', 'rb') as f:
    iaca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

trusted_certs = [iaca_cert]

# Verify with certificate chain validation AND hash verification
mdoc = MdocCbor()
mdoc.loads(device_response_bytes)
is_valid = mdoc.verify(trusted_root_certs=trusted_certs, verify_hashes=True)

if is_valid:
    print("Document signature, certificate chain, and element hashes are all valid")
```

### Verification Options

```python
# skip in doc examples (requires mdoc and trusted_certs from previous context)
# Full verification (default)
mdoc.verify(trusted_root_certs=trusted_certs, verify_hashes=True)

# Skip hash verification (only check signatures and certificate chain)
mdoc.verify(trusted_root_certs=trusted_certs, verify_hashes=False)

# Skip certificate chain validation (only check signatures and hashes)
mdoc.verify(verify_hashes=True)

# Only signature verification (not recommended for production)
mdoc.verify(verify_hashes=False)
```

### Accessing Verification Results

```python
# skip in doc examples (requires mdoc and trusted_certs from previous context)
mdoc.verify(trusted_root_certs=trusted_certs, verify_hashes=True)

for doc in mdoc.documents:
    # Certificate chain information
    mso = doc.issuersigned.issuer_auth
    if mso.verified_root:
        print(f"Document signed by: {mso.verified_root.subject}")
    
    # Hash verification results
    if doc.hash_verification:
        hv = doc.hash_verification
        print(f"Total elements: {hv['total']}")
        print(f"Verified: {hv['verified']}")
        print(f"Valid: {hv['valid']}")
        
        if hv['failed']:
            print(f"Failed verifications: {len(hv['failed'])}")
            for failure in hv['failed']:
                print(f"  - {failure['namespace']}/{failure['elementIdentifier']}: {failure['reason']}")
```

## Element Hash Verification

### How It Works

According to ISO 18013-5 §9.1.2.4, each disclosed data element is an `IssuerSignedItem`:

```cbor
IssuerSignedItem = {
  "digestID": int,              ; Unique identifier
  "random": bytes(32),          ; Random value for privacy
  "elementIdentifier": string,  ; Field name (e.g., "family_name")
  "elementValue": any           ; Field value
}
```

The hash verification process:

1. **Extract** the `IssuerSignedItem` from the namespace (wrapped in CBOR Tag 24)
2. **Compute** SHA-256 hash of the complete tagged bytes (including Tag 24 prefix)
3. **Compare** with the expected hash in `MSO.valueDigests[namespace][digestID]`

### Critical Implementation Detail

⚠️ **The hash MUST be computed on the complete CBOR Tag 24 structure**, not just the content:

```python
# skip in doc examples (illustrative snippet; item_content from context)
# CORRECT: Hash includes the Tag 24 wrapper
item_tag = CBORTag(24, item_content)
tagged_bytes = cbor2.dumps(item_tag)  # Includes d818... prefix
computed_hash = SHA256(tagged_bytes)

# INCORRECT: Hash only the content
computed_hash = SHA256(item_content)  # Will not match!
```

Example bytes structure:
- Content only: `a468646967657374...` (starts with `a4` = map with 4 elements)
- With Tag 24: `d8185873a468646967657374...` (prefix `d81858XX` = Tag 24 + length)

### Hash Verification Results

The `hash_verification` attribute contains:

```python
# skip in doc examples (structure documentation only)
{
    'valid': bool,        # True if all hashes match
    'total': int,         # Total number of elements checked
    'verified': int,      # Number of successfully verified elements
    'failed': [           # List of failed verifications
        {
            'namespace': str,
            'digestID': int,
            'elementIdentifier': str,
            'reason': str,
            'expected': str,  # Expected hash (hex) - if hash mismatch
            'computed': str   # Computed hash (hex) - if hash mismatch
        }
    ]
}
```

## Certificate Formats

### Trusted Root Certificates

The `trusted_root_certs` parameter accepts a list of `cryptography.x509.Certificate` objects. These are typically IACA (Issuer Authority Certification Authority) certificates.

**Supported input formats:**

```python
# skip in doc examples (requires cert.pem / cert.der on disk)
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# From PEM file
with open('cert.pem', 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read(), default_backend())

# From DER file
with open('cert.der', 'rb') as f:
    cert = x509.load_der_x509_certificate(f.read(), default_backend())

# From PEM string
pem_data = """-----BEGIN CERTIFICATE-----
MIIDHTCCAsSgAwIBAgISESEhmoph1P1OOjDCLJAgGdBbMAoGCCqGSM49BAMCMIGf
...
-----END CERTIFICATE-----"""
cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
```

### Document Signer (DS) Certificate

The DS certificate is automatically extracted from the mDOC's Mobile Security Object (MSO). It is embedded in the COSE_Sign1 structure's unprotected header (label 33).

## Certificate Chain Structure

```
┌─────────────────────────────────┐
│  Trusted Root Certificate       │
│  (IACA - provided by you)        │
└────────────┬────────────────────┘
             │ signs
             ▼
┌─────────────────────────────────┐
│  Document Signer Certificate    │
│  (DS - embedded in mDOC)         │
└────────────┬────────────────────┘
             │ signs
             ▼
┌─────────────────────────────────┐
│  Mobile Security Object (MSO)   │
│  (contains data element hashes) │
└─────────────────────────────────┘
```

## Error Handling

```python
# skip in doc examples (requires mdoc and trusted_certs from previous context)
try:
    is_valid = mdoc.verify(trusted_root_certs=trusted_certs, verify_hashes=True)
    if not is_valid:
        print("Verification failed")
        
        # Check which documents failed
        for doc in mdoc.documents_invalid:
            print(f"Invalid document: {doc.doctype}")
            
            # Check hash verification results
            if hasattr(doc, 'hash_verification') and doc.hash_verification:
                hv = doc.hash_verification
                if not hv['valid']:
                    print(f"  Hash verification failed: {len(hv['failed'])} elements")
                    for failure in hv['failed']:
                        print(f"    - {failure}")
        
except ValueError as e:
    if "not signed by any trusted root" in str(e):
        print("DS certificate not trusted")
    elif "not yet valid" in str(e):
        print("DS certificate not yet valid")
    elif "expired" in str(e):
        print("DS certificate has expired")
    else:
        print(f"Validation error: {e}")
```

### Common Hash Verification Failures

| Reason | Description | Solution |
|--------|-------------|----------|
| `hash mismatch` | Computed hash doesn't match MSO | Data has been tampered with or incorrectly encoded |
| `digestID not in MSO` | Element's digestID not found in MSO | MSO is incomplete or element is not authorized |
| `exception: ...` | Error during verification | Check CBOR encoding and data structure |

## Security Considerations

1. **Always provide trusted root certificates** in production environments
2. **Always enable hash verification** (`verify_hashes=True`) in production
3. **Keep root certificates up to date** - expired roots will cause validation failures
4. **Verify certificate validity dates** - the library checks `not_valid_before_utc` and `not_valid_after_utc`
5. **Use official IACA certificates** from trusted sources (government authorities, standards bodies)
6. **Never skip validations** in production - warnings are for testing only
7. **Check hash verification results** - a single failed hash indicates potential tampering

### Why Hash Verification Matters

Hash verification ensures:
- **Data Integrity**: Disclosed elements haven't been modified since issuance
- **Authorization**: Only elements authorized by the issuer are disclosed
- **Non-repudiation**: The issuer cannot deny having issued the data

Without hash verification, an attacker could:
- Modify element values while keeping valid signatures
- Add unauthorized elements to the disclosure
- Present elements from different documents

## Example: Managing Multiple Root Certificates

```python
# skip in doc examples (requires device_response_bytes; loads certs from /etc/mdoc/trusted_certs)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pathlib import Path

def load_trusted_certificates(cert_dir: Path) -> list:
    """Load all PEM certificates from a directory."""
    trusted_certs = []
    
    for cert_file in cert_dir.glob("*.pem"):
        with open(cert_file, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            trusted_certs.append(cert)
    
    return trusted_certs

# Load all trusted roots
trusted_certs = load_trusted_certificates(Path("/etc/mdoc/trusted_certs"))

# Verify document
mdoc = MdocCbor()
mdoc.loads(device_response_bytes)
is_valid = mdoc.verify(trusted_root_certs=trusted_certs)
```

## API Reference

### `MdocCbor.verify(trusted_root_certs=None, verify_hashes=True)`

Verify all documents in the mDOC.

**Parameters:**
- `trusted_root_certs` (list, optional): List of `cryptography.x509.Certificate` objects representing trusted root certificates. If `None`, certificate chain validation is skipped.
- `verify_hashes` (bool, optional): If `True` (default), verify element hashes against MSO valueDigests. Set to `False` to skip hash verification.

**Returns:**
- `bool`: `True` if all documents are valid, `False` otherwise

**Raises:**
- `ValueError`: If certificate chain validation fails

### `MobileDocument.verify(trusted_root_certs=None, verify_hashes=True)`

Verify a single document.

**Parameters:**
- `trusted_root_certs` (list, optional): List of trusted root certificates
- `verify_hashes` (bool, optional): If `True` (default), verify element hashes

**Returns:**
- `bool`: `True` if the document is valid, `False` otherwise

### `MsoVerifier.verified_root`

After calling `verify()` with `trusted_root_certs`, this attribute contains the trusted root certificate that successfully verified the DS certificate.

**Type:** `cryptography.x509.Certificate` or `None`

### `MobileDocument.hash_verification`

After calling `verify()` with `verify_hashes=True`, this attribute contains the hash verification results.

**Type:** `dict` or `None`

**Structure:**
```python
{
    'valid': bool,        # Overall result
    'total': int,         # Total elements checked
    'verified': int,      # Successfully verified
    'failed': list        # List of failures (see above)
}
```

### `MsoVerifier.verify_element_hashes(namespaces)`

Verify element hashes against MSO valueDigests.

**Parameters:**
- `namespaces` (dict): The nameSpaces dict from IssuerSigned containing IssuerSignedItems

**Returns:**
- `dict`: Verification results with keys: `valid`, `total`, `verified`, `failed`

## Backward Compatibility

Both verification features are fully backward compatible:

**Certificate Chain Verification:**
- Existing code that calls `verify()` without `trusted_root_certs` will continue to work
- A warning message will be logged recommending to enable chain validation

**Hash Verification:**
- Enabled by default (`verify_hashes=True`)
- Can be disabled by passing `verify_hashes=False` for backward compatibility
- Does not break existing code

## Complete Example

```python
# skip in doc examples (requires device_response_bytes; uses Path for trusted certs)
from pymdoccbor.mdoc.verifier import MdocCbor
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pathlib import Path

def load_trusted_certificates(cert_dir: Path) -> list:
    """Load all PEM certificates from a directory."""
    trusted_certs = []
    for cert_file in cert_dir.glob("*.pem"):
        with open(cert_file, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            trusted_certs.append(cert)
    return trusted_certs

def verify_mdoc(device_response_bytes: bytes, trusted_cert_dir: Path) -> dict:
    """
    Verify an mDOC with full validation.
    
    Returns:
        dict with keys: valid, certificate_info, hash_results
    """
    # Load trusted certificates
    trusted_certs = load_trusted_certificates(trusted_cert_dir)
    
    # Parse and verify
    mdoc = MdocCbor()
    mdoc.loads(device_response_bytes)
    is_valid = mdoc.verify(trusted_root_certs=trusted_certs, verify_hashes=True)
    
    results = {
        'valid': is_valid,
        'documents': []
    }
    
    # Collect results for each document
    for doc in mdoc.documents:
        doc_result = {
            'doctype': doc.doctype,
            'valid': doc.is_valid
        }
        
        # Certificate information
        mso = doc.issuersigned.issuer_auth
        if mso.verified_root:
            doc_result['certificate'] = {
                'subject': str(mso.verified_root.subject),
                'issuer': str(mso.verified_root.issuer),
                'not_before': mso.verified_root.not_valid_before_utc,
                'not_after': mso.verified_root.not_valid_after_utc
            }
        
        # Hash verification results
        if doc.hash_verification:
            doc_result['hash_verification'] = doc.hash_verification
        
        results['documents'].append(doc_result)
    
    return results

# Usage
device_response = bytes.fromhex("...")
results = verify_mdoc(device_response, Path("/etc/mdoc/trusted_certs"))

if results['valid']:
    print("✓ mDOC is valid")
    for doc in results['documents']:
        print(f"  Document: {doc['doctype']}")
        print(f"  Certificate: {doc['certificate']['subject']}")
        print(f"  Elements verified: {doc['hash_verification']['verified']}/{doc['hash_verification']['total']}")
else:
    print("✗ mDOC verification failed")
```
