from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MobileDocument
from pymdoccbor.tests.cert_data import CERT_DATA
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.tests.pkey import PKEY


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

    document = mdoc.signed["documents"][0]
    doc = MobileDocument(**document)

    assert doc.doctype == "org.micov.medical.1"
    assert doc.issuersigned


def test_mobile_document_dump():
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

    document = mdoc.signed["documents"][0]
    doc = MobileDocument(**document)

    dump = doc.dump()
    assert dump
    assert isinstance(dump, bytes)
    assert len(dump) > 0


def test_mobile_document_dumps():
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

    document = mdoc.signed["documents"][0]
    doc = MobileDocument(**document)

    dumps = doc.dumps()
    assert dumps
    assert isinstance(dumps, bytes)
    assert len(dumps) > 0


def test_mobile_document_verify():
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

    document = mdoc.signed["documents"][0]
    doc = MobileDocument(**document)

    assert doc.verify()
