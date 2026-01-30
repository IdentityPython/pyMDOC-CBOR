from pycose.messages import CoseMessage

from pymdoccbor.mso.issuer import MsoIssuer
from pymdoccbor.tests.cert_data import CERT_DATA
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.tests.pkey import PKEY


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
