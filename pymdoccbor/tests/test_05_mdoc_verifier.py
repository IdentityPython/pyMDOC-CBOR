import os
from pymdoccbor.mdoc.verifier import MobileDocument
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.tests.micov_data import MICOV_DATA

PKEY = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': os.urandom(32),
    'KID': b"demo-kid"
}

mdoc = MdocCborIssuer(PKEY)
mdoc.new(
    data=MICOV_DATA,
    devicekeyinfo=PKEY,  # TODO
    doctype="org.micov.medical.1"
)

def test_verifier_must_fail_document_type():
    try:
        MobileDocument(None, None)
    except Exception as e:
        assert str(e) == "You must provide a document type"

def test_verifier_must_fail_issuer_signed():
    try:
        MobileDocument("org.micov.medical.1", None)
    except Exception as e:
        assert str(e) == "You must provide a signed document"

def test_mobile_document():
    document = mdoc.signed["documents"][0]
    doc = MobileDocument(**document)

    assert doc.doctype == "org.micov.medical.1"
    assert doc.issuersigned

def test_mobile_document_dump():
    document = mdoc.signed["documents"][0]
    doc = MobileDocument(**document)

    dump = doc.dump()
    assert dump
    assert isinstance(dump, bytes)
    assert len(dump) > 0

def test_mobile_document_dumps():
    document = mdoc.signed["documents"][0]
    doc = MobileDocument(**document)

    dumps = doc.dumps()
    assert dumps
    assert isinstance(dumps, bytes)
    assert len(dumps) > 0

def test_mobile_document_verify():
    document = mdoc.signed["documents"][0]
    doc = MobileDocument(**document)

    #assert mdoc.verify() == True