# Fix: Support for 'errors' field in MobileDocument

## Problem

ISO 18013-5 specifies that when a Device Response has `status != 0`, documents may contain an `errors` field describing which elements were not available or could not be returned.

Example from real-world France Identité CNI:
```python
{
    'version': '1.0',
    'documents': [{
        'docType': 'eu.europa.ec.eudi.pid.1',
        'issuerSigned': {...},
        'errors': {
            'eu.europa.ec.eudi.pid.1': {
                'some_element': 1  # Error code
            }
        }
    }],
    'status': 20  # Elements not present
}
```

Previously, pyMDOC-CBOR v1.0.1 would raise:
```
TypeError: MobileDocument.__init__() got an unexpected keyword argument 'errors'
```

## Solution

Added support for the optional `errors` parameter in `MobileDocument.__init__()`:

### Changes in `pymdoccbor/mdoc/verifier.py`

1. **Updated `__init__` signature**:
```python
def __init__(self, docType: str, issuerSigned: dict, deviceSigned: dict = {}, errors: dict = None) -> None:
    # ...
    self.errors: dict = errors if errors is not None else {}
```

2. **Updated `dump()` method** to include errors when present:
```python
def dump(self) -> bytes:
    doc_dict = {
        'docType': self.doctype,
        'issuerSigned': self.issuersigned.dumps()
    }
    
    # Include errors field if present (ISO 18013-5 status != 0)
    if self.errors:
        doc_dict['errors'] = self.errors
    
    return cbor2.dumps(cbor2.CBORTag(24, value=doc_dict))
```

## Backward Compatibility

✅ Fully backward compatible:
- `errors` parameter is optional (defaults to `None`)
- When `errors` is empty or `None`, it's not included in `dump()` output
- All existing tests pass (36/36)

## Tests

Added comprehensive test suite in `pymdoccbor/tests/test_09_errors_field.py`:

1. ✅ `test_mobile_document_with_errors_field` - Accepts errors field
2. ✅ `test_mobile_document_without_errors_field` - Works without errors (backward compat)
3. ✅ `test_mobile_document_dump_with_errors` - Includes errors in dump when present
4. ✅ `test_mobile_document_dump_without_errors` - Excludes errors from dump when empty

All tests pass: **36/36 passed**

## Usage

### With errors field (status != 0)
```python
import os
from datetime import datetime, timezone, timedelta
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MobileDocument

CERT_INFO = {
    "country_name": "IT",
    "organization_name": "Example",
    "common_name": "Example mDL",
    "not_valid_before": datetime.now(timezone.utc) - timedelta(days=1),
    "not_valid_after": datetime.now(timezone.utc) + timedelta(days=365),
}
PKEY = {"KTY": "EC2", "CURVE": "P_256", "ALG": "ES256", "D": os.urandom(32), "KID": b"kid"}
DATA = {"org.micov.medical.1": {"family_name": "Test", "given_name": "User"}}

issuer = MdocCborIssuer(private_key=PKEY, alg="ES256", cert_info=CERT_INFO)
issuer.new(data=DATA, doctype="org.micov.medical.1", validity={"issuance_date": "2025-01-01", "expiry_date": "2025-12-31"})
document = issuer.signed["documents"][0]
document["errors"] = {"org.micov.medical.1": {"missing_element": 1}}

doc = MobileDocument(**document)
assert doc.errors == {"org.micov.medical.1": {"missing_element": 1}}
```

### Without errors field (status == 0)
```python
import os
from datetime import datetime, timezone, timedelta
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MobileDocument

CERT_INFO = {
    "country_name": "IT",
    "organization_name": "Example",
    "common_name": "Example mDL",
    "not_valid_before": datetime.now(timezone.utc) - timedelta(days=1),
    "not_valid_after": datetime.now(timezone.utc) + timedelta(days=365),
}
PKEY = {"KTY": "EC2", "CURVE": "P_256", "ALG": "ES256", "D": os.urandom(32), "KID": b"kid"}
DATA = {"org.micov.medical.1": {"family_name": "Test", "given_name": "User"}}

issuer = MdocCborIssuer(private_key=PKEY, alg="ES256", cert_info=CERT_INFO)
issuer.new(data=DATA, doctype="org.micov.medical.1", validity={"issuance_date": "2025-01-01", "expiry_date": "2025-12-31"})
document = issuer.signed["documents"][0]

doc = MobileDocument(**document)
assert doc.errors == {}
```

## ISO 18013-5 Reference

From ISO/IEC 18013-5:2021, section 8.3.2.1.2.2:

> **status**: Status code indicating the result of the request
> - 0: OK
> - 10: General error
> - 20: CBOR decoding error
> - ...
>
> When status != 0, the `errors` field MAY be present to provide details about which elements could not be returned.

## Branch

Branch: `fix/support-errors-field`
