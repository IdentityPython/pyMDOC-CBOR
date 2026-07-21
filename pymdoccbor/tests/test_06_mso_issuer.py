import datetime

import cbor2
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


def test_mso_issuer_validity_same_day():
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
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
            return datetime.datetime.fromisoformat(dt.replace("Z", "+00:00"))
        return dt.replace(tzinfo=datetime.timezone.utc)

    signed = _as_utc(validity["signed"])
    valid_from = _as_utc(validity["validFrom"])
    valid_until = _as_utc(validity["validUntil"])

    assert valid_from <= signed <= valid_until
    assert valid_until.hour == 23 and valid_until.minute == 59 and valid_until.second == 59
