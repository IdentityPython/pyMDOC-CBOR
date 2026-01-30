"""
Test certificate chain verification and element hash verification.
"""

from datetime import datetime, timedelta, timezone

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MdocCbor, MobileDocument
from pymdoccbor.mso.verifier import MsoVerifier
from pymdoccbor.tests.cert_data import CERT_DATA
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.tests.pkey import PKEY


def generate_test_certificates():
    """Generate a test root CA and DS certificate for testing."""
    # Generate root CA private key
    root_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Create root CA certificate
    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
    ])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    # Generate DS private key
    ds_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Create DS certificate signed by root CA
    ds_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test DS"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Document Signer"),
    ])

    ds_cert = (
        x509.CertificateBuilder()
        .subject_name(ds_subject)
        .issuer_name(root_subject)
        .public_key(ds_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    return root_cert, ds_cert, ds_key


def test_certificate_chain_verification_success():
    """Test successful certificate chain verification."""
    root_cert, ds_cert, ds_key = generate_test_certificates()

    # Create mdoc with DS certificate
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

    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]
    msov = MsoVerifier(issuerAuth)

    # Replace the certificate in the MSO with our test DS cert
    msov.x509_certificates = [ds_cert]

    # Verify with trusted root
    verified_root = msov.attest_public_key([root_cert])

    assert verified_root is not None
    assert verified_root == root_cert


def test_certificate_chain_verification_untrusted():
    """Test certificate chain verification with untrusted root."""
    root_cert, ds_cert, ds_key = generate_test_certificates()

    # Generate a different root that didn't sign the DS cert
    untrusted_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    untrusted_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted Root"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted Root CA"),
    ])
    untrusted_cert = (
        x509.CertificateBuilder()
        .subject_name(untrusted_subject)
        .issuer_name(untrusted_subject)
        .public_key(untrusted_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(untrusted_key, hashes.SHA256(), default_backend())
    )

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

    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]
    msov = MsoVerifier(issuerAuth)
    msov.x509_certificates = [ds_cert]

    # Should raise ValueError
    with pytest.raises(ValueError, match="not signed by any trusted root"):
        msov.attest_public_key([untrusted_cert])


def test_certificate_chain_verification_skipped():
    """Test that verification is skipped when no trusted roots provided."""
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

    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]
    msov = MsoVerifier(issuerAuth)

    # Should return None and log warning
    result = msov.attest_public_key(None)
    assert result is None


def test_element_hash_verification_success():
    """Test successful element hash verification."""
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

    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]
    namespaces = mdoc.signed["documents"][0]["issuerSigned"]["nameSpaces"]

    msov = MsoVerifier(issuerAuth)
    results = msov.verify_element_hashes(namespaces)

    assert results['valid'] is True
    assert results['total'] > 0
    assert results['verified'] == results['total']
    assert len(results['failed']) == 0


def test_element_hash_verification_tampered():
    """Test element hash verification with tampered data."""
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

    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]
    namespaces = mdoc.signed["documents"][0]["issuerSigned"]["nameSpaces"]

    # Tamper with an element
    namespace_key = list(namespaces.keys())[0]
    if namespaces[namespace_key]:
        first_item = namespaces[namespace_key][0]
        # first_item is already a CBORTag object
        if isinstance(first_item, cbor2.CBORTag):
            item_content = cbor2.loads(first_item.value)
            item_content['elementValue'] = 'TAMPERED'
            # Re-encode
            namespaces[namespace_key][0] = cbor2.CBORTag(24, cbor2.dumps(item_content))

    msov = MsoVerifier(issuerAuth)
    results = msov.verify_element_hashes(namespaces)

    assert results['valid'] is False
    assert results['total'] > 0
    assert results['verified'] < results['total']
    assert len(results['failed']) > 0
    assert results['failed'][0]['reason'] == 'hash mismatch'


def test_mobile_document_verify_with_hashes():
    """Test MobileDocument.verify() with hash verification enabled."""
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

    # Verify with hash verification enabled
    is_valid = doc.verify(verify_hashes=True)

    assert is_valid is True
    assert doc.hash_verification is not None
    assert doc.hash_verification['valid'] is True
    assert doc.hash_verification['total'] > 0


def test_mobile_document_verify_without_hashes():
    """Test MobileDocument.verify() with hash verification disabled."""
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

    # Verify with hash verification disabled
    is_valid = doc.verify(verify_hashes=False)

    assert is_valid is True
    assert doc.hash_verification is None


def test_mdoc_cbor_verify_with_all_features():
    """Test MdocCbor.verify() with certificate chain and hash verification."""
    root_cert, ds_cert, ds_key = generate_test_certificates()

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

    # Use the full signed structure, not just dumps()
    mdoc_cbor = MdocCbor()
    mdoc_cbor.loads(cbor2.dumps(mdoc.signed))

    # Verify with hash verification (cert chain will be skipped without trusted roots)
    is_valid = mdoc_cbor.verify(verify_hashes=True)

    assert is_valid is True
    assert len(mdoc_cbor.documents) > 0
    assert mdoc_cbor.documents[0].hash_verification is not None
    assert mdoc_cbor.documents[0].hash_verification['valid'] is True
