from pycose.messages import CoseMessage

from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mso.verifier import MsoVerifier
from pymdoccbor.tests.cert_data import CERT_DATA
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.tests.pkey import PKEY

mdoc = MdocCborIssuer(
    private_key=PKEY,
    alg="ES256",
    cert_info=CERT_DATA
)

mdoc.new(
    data=MICOV_DATA,
    # devicekeyinfo=PKEY,  # TODO
    doctype="org.micov.medical.1",
    validity={
        "issuance_date": "2024-12-31",
        "expiry_date": "2050-12-31"
    },
)


def test_mso_verifier_fail():
    try:
        MsoVerifier(None)
    except Exception as e:
        assert str(e) == "MsoParser only supports raw bytes and list, a <class 'NoneType'> was provided"


def test_mso_verifier_creation():
    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]

    msov = MsoVerifier(issuerAuth)

    assert isinstance(msov.object, CoseMessage)


def test_mso_verifier_verify_signatures():
    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]

    msov = MsoVerifier(issuerAuth)

    assert msov.verify_signature()


def test_mso_verifier_payload_as_cbor():
    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]

    msov = MsoVerifier(issuerAuth)

    cbor = msov.payload_as_dict

    assert cbor
    assert cbor["version"] == "1.0"
    assert cbor["digestAlgorithm"] == "SHA-256"
    assert cbor["valueDigests"]["org.micov.medical.1"]


def test_payload_as_raw():
    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]

    msov = MsoVerifier(issuerAuth)

    raw = msov.payload_as_raw

    assert raw
    assert isinstance(raw, bytes)
    assert len(raw) > 0
