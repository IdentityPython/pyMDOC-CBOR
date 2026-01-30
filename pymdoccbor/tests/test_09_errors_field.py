"""
Test support for the 'errors' field in MobileDocument.

ISO 18013-5 specifies that when status != 0, documents may contain
an 'errors' field describing which elements were not available.
"""

from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MobileDocument
from pymdoccbor.tests.cert_data import CERT_DATA
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.tests.pkey import PKEY


def test_mobile_document_with_errors_field():
    """Test that MobileDocument accepts an 'errors' field."""
    mdoc = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
        cert_info=CERT_DATA
    )
    mdoc.new(
        data=MICOV_DATA,
        doctype="org.micov.medical.1",
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
    )

    document = mdoc.signed["documents"][0]

    # Add errors field (simulating status 20 - elements not present)
    document['errors'] = {
        'org.micov.medical.1': {
            'missing_element': 1  # Error code for element not present
        }
    }

    # Should not raise TypeError
    doc = MobileDocument(**document)

    assert doc.doctype == "org.micov.medical.1"
    assert doc.errors is not None
    assert isinstance(doc.errors, dict)


def test_mobile_document_without_errors_field():
    """Test that MobileDocument works without 'errors' field (backward compatibility)."""
    mdoc = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
        cert_info=CERT_DATA
    )
    mdoc.new(
        data=MICOV_DATA,
        doctype="org.micov.medical.1",
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
    )

    document = mdoc.signed["documents"][0]

    # No errors field
    doc = MobileDocument(**document)

    assert doc.doctype == "org.micov.medical.1"
    assert doc.errors == {}  # Should default to empty dict


def test_mobile_document_dump_with_errors():
    """Test that dump() includes errors field when present."""
    mdoc = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
        cert_info=CERT_DATA
    )
    mdoc.new(
        data=MICOV_DATA,
        doctype="org.micov.medical.1",
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
    )

    document = mdoc.signed["documents"][0]

    # Add errors field
    errors_data = {
        'org.micov.medical.1': {
            'missing_element': 1
        }
    }
    document['errors'] = errors_data

    doc = MobileDocument(**document)
    dump = doc.dump()

    assert dump
    assert isinstance(dump, bytes)

    # Decode and verify errors field is present
    import cbor2
    decoded = cbor2.loads(dump)
    # The dump is wrapped in a CBORTag, so we need to access .value
    if hasattr(decoded, 'value'):
        decoded = decoded.value

    assert 'errors' in decoded
    assert decoded['errors'] == errors_data


def test_mobile_document_dump_without_errors():
    """Test that dump() works without errors field (backward compatibility)."""
    mdoc = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
        cert_info=CERT_DATA
    )
    mdoc.new(
        data=MICOV_DATA,
        doctype="org.micov.medical.1",
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
    )

    document = mdoc.signed["documents"][0]
    doc = MobileDocument(**document)

    dump = doc.dump()

    assert dump
    assert isinstance(dump, bytes)

    # Decode and verify errors field is NOT present
    import cbor2
    decoded = cbor2.loads(dump)
    if hasattr(decoded, 'value'):
        decoded = decoded.value

    # errors field should not be in dump if it's empty
    assert 'errors' not in decoded
