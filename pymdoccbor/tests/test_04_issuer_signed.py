from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.issuersigned import IssuerSigned
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
issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]
issuer_signed = IssuerSigned(**issuerAuth)


def test_issuer_signed_fail():
    try:
        IssuerSigned(None, None)
    except Exception as e:
        assert str(e) == "issuerAuth must be provided"


def test_issuer_signed_creation():
    assert issuer_signed.namespaces
    assert issuer_signed.issuer_auth


def test_issuer_signed_dump():
    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]

    issuer_signed = IssuerSigned(**issuerAuth)

    dump = issuer_signed.dump()
    assert dump
    assert dump["nameSpaces"] == issuer_signed.namespaces
    assert dump["issuerAuth"] == issuer_signed.issuer_auth


def test_issuer_signed_dumps():
    issuerAuth = mdoc.signed["documents"][0]["issuerSigned"]

    issuer_signed = IssuerSigned(**issuerAuth)

    dumps = issuer_signed.dumps()
    assert dumps
    assert isinstance(dumps, bytes)
    assert len(dumps) > 0
