import os
from pymdoccbor.mdoc.issuersigned import IssuerSigned
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.tests.micov_data import MICOV_DATA

PKEY = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': os.urandom(32),
    'KID': b"demo-kid"
}

issuer_signed = None

def test_issuer_signed_fail():
    try:
        IssuerSigned(None, None)
    except Exception as e:
        assert str(e) == "issuerAuth must be provided"

def test_issuer_signed_creation():
    issued_doc = MdocCborIssuer(PKEY)
    issued_doc.new(
        data=MICOV_DATA,
        devicekeyinfo=PKEY,
        doctype="org.micov.medical.1"
    )

    issuerAuth = issued_doc.signed["documents"][0]["issuerSigned"]

    issuer_signed = IssuerSigned(**issuerAuth)

    assert issuer_signed.namespaces
    assert issuer_signed.issuer_auth

def test_issuer_signed_dump():
    issued_doc = MdocCborIssuer(PKEY)
    issued_doc.new(
        data=MICOV_DATA,
        devicekeyinfo=PKEY,
        doctype="org.micov.medical.1"
    )

    issuerAuth = issued_doc.signed["documents"][0]["issuerSigned"]

    issuer_signed = IssuerSigned(**issuerAuth)

    dump = issuer_signed.dump()
    assert dump
    assert dump["nameSpaces"] == issuer_signed.namespaces
    assert dump["issuerAuth"] == issuer_signed.issuer_auth

def test_issuer_signed_dumps():
    issued_doc = MdocCborIssuer(PKEY)
    issued_doc.new(
        data=MICOV_DATA,
        devicekeyinfo=PKEY,
        doctype="org.micov.medical.1"
    )

    issuerAuth = issued_doc.signed["documents"][0]["issuerSigned"]

    issuer_signed = IssuerSigned(**issuerAuth)

    dumps = issuer_signed.dumps()
    assert dumps
    assert isinstance(dumps, bytes)
    assert len(dumps) > 0