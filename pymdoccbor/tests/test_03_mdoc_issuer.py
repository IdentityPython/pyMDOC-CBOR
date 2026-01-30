from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.tests.cert_data import CERT_DATA
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.tests.pkey import PKEY

mdoc = MdocCborIssuer(
    private_key=PKEY,
    alg="ES256",
    cert_info=CERT_DATA
)


def test_MdocCborIssuer_creation():
    assert mdoc.version == '1.0'
    assert mdoc.status == 0


def test_mdoc_without_private_key_must_fail():
    try:
        MdocCborIssuer(None)
    except Exception as e:
        assert str(e) == "You must provide a private key"


def test_MdocCborIssuer_new_single():
    mdoc.new(
        data=MICOV_DATA,
        # devicekeyinfo=PKEY,  # TODO
        doctype="org.micov.medical.1",
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
    )
    assert mdoc.signed['version'] == '1.0'
    assert mdoc.signed['status'] == 0
    assert mdoc.signed['documents'][0]['docType'] == 'org.micov.medical.1'
    assert mdoc.signed['documents'][0]['issuerSigned']['nameSpaces']['org.micov.medical.1'][0].tag == 24

# TODO: restore multiple documents support
# def test_MdocCborIssuer_new_multiple():
#     micov_data = {"doctype": "org.micov.medical.1", "data": MICOV_DATA}
#     pid_data = {"doctype": "eu.europa.ec.eudiw.pid.1", "data": PID_DATA}
#     mdoc.new(
#         doctype="org.micov.medical.1",
#         data=[micov_data, pid_data],
#         validity={"issuance_date": "2024-12-31", "expiry_date": "2050-12-31"},
#         # devicekeyinfo=PKEY  # TODO
#     )
#     assert mdoc.signed['version'] == '1.0'
#     assert mdoc.signed['documents'][0]['docType'] == 'org.micov.medical.1'
#     assert mdoc.signed['documents'][1]['docType'] == 'eu.europa.ec.eudiw.pid.1'


def test_MdocCborIssuer_dump():
    dump = mdoc.dump()

    assert dump
    assert isinstance(dump, bytes)
    assert len(dump) > 0


def test_MdocCborIssuer_dumps():
    dumps = mdoc.dumps()

    assert dumps
    assert isinstance(dumps, bytes)
    assert len(dumps) > 0
