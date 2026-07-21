from datetime import datetime, timedelta, timezone

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pycose.headers import X5chain
from pycose.messages import CoseMessage

from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mso.issuer import MsoIssuer
from pymdoccbor.mso.verifier import MsoVerifier
from pymdoccbor.tests.cert_data import CERT_DATA
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.tests.pkey import PKEY


def _generate_test_certificates():
    root_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
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

    ds_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
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

    return root_cert, ds_cert


def _validity():
    return {"issuance_date": "2024-12-31", "expiry_date": "2050-12-31"}


def _issuer_auth_x5chain(issuer_auth):
    msov = MsoVerifier(issuer_auth)
    return msov.raw_public_keys


def test_mso_issuer_fail():
    try:
        MsoIssuer(None, None)
    except Exception as e:
        assert str(e) == "MSO Writer requires a valid private key"


def test_mso_issuer_creation():
    msoi = MsoIssuer(
        data=MICOV_DATA,
        private_key=PKEY,
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
        alg="ES256",
        cert_info=CERT_DATA
    )

    assert msoi.private_key
    assert msoi.data
    assert msoi.hash_map
    assert list(msoi.hash_map.keys())[0] == 'org.micov.medical.1'
    assert msoi.disclosure_map['org.micov.medical.1']


def test_mso_issuer_sign():
    msoi = MsoIssuer(
        data=MICOV_DATA,
        private_key=PKEY,
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
        alg="ES256",
        cert_info=CERT_DATA
    )

    mso = msoi.sign()
    assert isinstance(mso, CoseMessage)


def test_mso_issuer_x509_chain_single_certificate():
    _, ds_cert = _generate_test_certificates()

    msoi = MsoIssuer(
        data=MICOV_DATA,
        private_key=PKEY,
        validity=_validity(),
        alg="ES256",
        x509_chain=[ds_cert],
    )

    mso = msoi.sign()
    x5chain = mso.uhdr[X5chain]

    assert isinstance(x5chain, bytes)
    assert x5chain == ds_cert.public_bytes(serialization.Encoding.DER)


def test_mso_issuer_x509_chain_multiple_certificates():
    root_cert, ds_cert = _generate_test_certificates()

    msoi = MsoIssuer(
        data=MICOV_DATA,
        private_key=PKEY,
        validity=_validity(),
        alg="ES256",
        x509_chain=[ds_cert, root_cert],
    )

    mso = msoi.sign()
    x5chain = mso.uhdr[X5chain]

    assert isinstance(x5chain, list)
    assert len(x5chain) == 2
    assert x5chain[0] == ds_cert.public_bytes(serialization.Encoding.DER)
    assert x5chain[1] == root_cert.public_bytes(serialization.Encoding.DER)


def test_mso_issuer_cert_path_and_x509_chain_are_mutually_exclusive():
    _, ds_cert = _generate_test_certificates()

    with pytest.raises(ValueError, match="mutually exclusive"):
        MsoIssuer(
            data=MICOV_DATA,
            private_key=PKEY,
            validity=_validity(),
            alg="ES256",
            cert_path="unused.pem",
            x509_chain=[ds_cert],
        )


def test_mdoc_cbor_issuer_x509_chain_in_issuer_auth():
    root_cert, ds_cert = _generate_test_certificates()

    mdoc = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
        cert_info=CERT_DATA,
    )
    mdoc.new(
        data=MICOV_DATA,
        doctype="org.micov.medical.1",
        validity=_validity(),
        x509_chain=[ds_cert, root_cert],
    )

    issuer_auth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]
    x5chain = _issuer_auth_x5chain(issuer_auth)

    assert len(x5chain) == 2
    assert x5chain[0] == ds_cert.public_bytes(serialization.Encoding.DER)
    assert x5chain[1] == root_cert.public_bytes(serialization.Encoding.DER)


def test_mso_issuer_validity_same_day():
    today = datetime.utcnow().strftime("%Y-%m-%d")
    msoi = MsoIssuer(
        data=MICOV_DATA,
        private_key=PKEY,
        validity={"issuance_date": today, "expiry_date": today},
        alg="ES256",
        cert_info=CERT_DATA,
    )

    mso = msoi.sign()
    payload = cbor2.loads(mso.payload)
    mso_body = cbor2.loads(payload.value)
    validity = mso_body["validityInfo"]

    def _as_utc(dt):
        if isinstance(dt, cbor2.CBORTag):
            dt = dt.value
        if isinstance(dt, str):
            return datetime.fromisoformat(dt.replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc)

    signed = _as_utc(validity["signed"])
    valid_from = _as_utc(validity["validFrom"])
    valid_until = _as_utc(validity["validUntil"])

    assert valid_from <= signed <= valid_until
    assert valid_until.hour == 23 and valid_until.minute == 59 and valid_until.second == 59
