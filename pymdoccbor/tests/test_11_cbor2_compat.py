"""Compatibility with cbor2 >= 6 (immutable tuple / frozendict decode)."""
import cbor2
from pycose.messages import Sign1Message

from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MobileDocument
from pymdoccbor.mso.verifier import MsoVerifier
from pymdoccbor.tests.cert_data import CERT_DATA
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.tests.pkey import PKEY
from pymdoccbor.tools import cborlist2CoseSign1, thaw_cbor


def test_thaw_cbor_tuple_and_mapping():
    tagged = cbor2.dumps(cbor2.CBORTag(18, [b"\xa1\x01&", {33: b"cert"}, b"pay", b"sig"]))
    loaded = cbor2.loads(tagged)
    # cbor2 5 -> list/dict; cbor2 6 -> tuple/frozendict
    thawed = thaw_cbor(loaded)
    assert isinstance(thawed, cbor2.CBORTag)
    assert isinstance(thawed.value, list)
    assert isinstance(thawed.value[1], dict)
    assert thawed.value[1][33] == b"cert"


def test_cborlist2CoseSign1_accepts_tuple():
    cose_tuple = (b"\xa1\x01&", {33: b"cert"}, b"pay", b"sig")
    msg = cborlist2CoseSign1(cose_tuple)
    assert isinstance(msg, Sign1Message)
    assert msg.payload == b"pay"


def test_mso_verifier_with_cbor2_loads_roundtrip():
    mdoc = MdocCborIssuer(private_key=PKEY, alg="ES256", cert_info=CERT_DATA)
    mdoc.new(
        data=MICOV_DATA,
        doctype="org.micov.medical.1",
        validity={"issuance_date": "2024-12-31", "expiry_date": "2050-12-31"},
    )
    issuer_auth = mdoc.signed["documents"][0]["issuerSigned"]["issuerAuth"]
    assert isinstance(issuer_auth, list)

    # Simulate cbor2 >= 6 decode of untagged COSE_Sign1
    reloaded = cbor2.loads(cbor2.dumps(issuer_auth))
    msov = MsoVerifier(reloaded)
    assert isinstance(msov.object, Sign1Message)
    assert msov.verify_signature()


def test_mobile_document_from_issuer_signed():
    mdoc = MdocCborIssuer(private_key=PKEY, alg="ES256", cert_info=CERT_DATA)
    mdoc.new(
        data=MICOV_DATA,
        doctype="org.micov.medical.1",
        validity={"issuance_date": "2024-12-31", "expiry_date": "2050-12-31"},
    )
    document = mdoc.signed["documents"][0]
    doc = MobileDocument(**document)
    assert doc.doctype == "org.micov.medical.1"
    assert doc.errors == {}
