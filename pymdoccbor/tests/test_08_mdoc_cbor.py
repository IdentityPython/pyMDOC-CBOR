import datetime

import cbor2

from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MdocCbor
from pymdoccbor.tests.cert_data import CERT_DATA
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.tests.pkey import PKEY


def normalize_dates(obj):
    if isinstance(obj, dict):
        return {k: normalize_dates(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [normalize_dates(v) for v in obj]
    elif isinstance(obj, datetime.date):
        return obj.isoformat()
    return obj


def test_mdoc_cbor_creation():
    mdoci = MdocCborIssuer(private_key=PKEY, alg="ES256", cert_info=CERT_DATA)
    mdoc = mdoci.new(
        data=MICOV_DATA,
        # devicekeyinfo=PKEY,  # TODO
        doctype="org.micov.medical.1",
        validity={"issuance_date": "2024-12-31", "expiry_date": "2050-12-31"},
        status={
            "status_list": {"idx": 412, "uri": "https://example.com/statuslists/1"}
        },
    )

    data = cbor2.dumps(mdoc, datetime_as_timestamp=True)

    mdocp = MdocCbor()
    mdocp.loads(data)
    mdocp.verify()

    assert mdoc
    assert "org.micov.medical.1" in mdocp.disclosure_map

    assert normalize_dates(mdocp.disclosure_map) == normalize_dates(MICOV_DATA)
    assert mdocp.status == {
        "status_list": {"idx": 412, "uri": "https://example.com/statuslists/1"}
    }


def test_mdoc_cbor_invalid_status():
    mdoci = MdocCborIssuer(private_key=PKEY, alg="ES256", cert_info=CERT_DATA)

    try:
        mdoci.new(
            data=MICOV_DATA,
            # devicekeyinfo=PKEY,  # TODO
            doctype="org.micov.medical.1",
            validity={"issuance_date": "2024-12-31", "expiry_date": "2050-12-31"},
            status={
                "status_list": {
                    "idx": 412,
                    # "uri": "https://example.com/statuslists/1"  # Missing URI
                }
            },
        )
    except Exception as e:
        assert str(e) == "uri is required"

    try:
        mdoci.new(
            data=MICOV_DATA,
            # devicekeyinfo=PKEY,  # TODO
            doctype="org.micov.medical.1",
            validity={"issuance_date": "2024-12-31", "expiry_date": "2050-12-31"},
            status={
                "status_list": {
                    # "idx": 412,
                    "uri": "https://example.com/statuslists/1"  # Missing URI
                }
            },
        )
    except Exception as e:
        assert str(e) == "idx is required"

    try:
        mdoci.new(
            data=MICOV_DATA,
            # devicekeyinfo=PKEY,  # TODO
            doctype="org.micov.medical.1",
            validity={"issuance_date": "2024-12-31", "expiry_date": "2050-12-31"},
            status={
                "not_status_list": {
                    "idx": 412,
                    "uri": "https://example.com/statuslists/1",  # Missing URI
                }
            },
        )
    except Exception as e:
        assert str(e) == "status_list is required"
