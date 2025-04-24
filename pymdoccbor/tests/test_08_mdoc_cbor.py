import os
import cbor2
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.mdoc.verifier import MdocCbor
from pymdoccbor.tests.pkey import PKEY

def test_mdoc_cbor_creation():
    mdoci = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
    )
    mdoc = mdoci.new(
        data=MICOV_DATA,
        #devicekeyinfo=PKEY,  # TODO
        doctype="org.micov.medical.1",
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
        status={
            "status_list": {
                "idx": 412,
                "uri": "https://example.com/statuslists/1"
            }
        }
    )

    data = cbor2.dumps(mdoc)  

    mdocp = MdocCbor()
    mdocp.loads(data)
    mdocp.verify()

    assert mdoc
    assert 'org.micov.medical.1' in mdocp.disclosure_map
    assert mdocp.disclosure_map == MICOV_DATA
    assert mdocp.status == {
        "status_list": {
            "idx": 412,
            "uri": "https://example.com/statuslists/1"
        }
    }

def test_mdoc_cbor_invalid_status():
    mdoci = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
    )

    try:
        mdoci.new(
            data=MICOV_DATA,
            #devicekeyinfo=PKEY,  # TODO
            doctype="org.micov.medical.1",
            validity={
                "issuance_date": "2024-12-31",
                "expiry_date": "2050-12-31"
            },
            status={
                "status_list": {
                    "idx": 412,
                    # "uri": "https://example.com/statuslists/1"  # Missing URI
                }
            }
        )
    except Exception as e:
        assert str(e) == "uri is required"

    try:
        mdoci.new(
            data=MICOV_DATA,
            #devicekeyinfo=PKEY,  # TODO
            doctype="org.micov.medical.1",
            validity={
                "issuance_date": "2024-12-31",
                "expiry_date": "2050-12-31"
            },
            status={
                "status_list": {
                    #"idx": 412,
                    "uri": "https://example.com/statuslists/1"  # Missing URI
                }
            }
        )
    except Exception as e:
        assert str(e) == "idx is required"

    try:
        mdoci.new(
            data=MICOV_DATA,
            #devicekeyinfo=PKEY,  # TODO
            doctype="org.micov.medical.1",
            validity={
                "issuance_date": "2024-12-31",
                "expiry_date": "2050-12-31"
            },
            status={
                "not_status_list": {
                    "idx": 412,
                    "uri": "https://example.com/statuslists/1"  # Missing URI
                }
            }
        )
    except Exception as e:
        assert str(e) == "status_list is required"