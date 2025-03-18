import cbor2
import os
from pycose.messages import Sign1Message

from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MdocCbor
from pymdoccbor.mso.issuer import MsoIssuer
from . pid_data import PID_DATA


PKEY = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': os.urandom(32),
    'KID': b"demo-kid"
}


def test_mso_writer():
    msoi = MsoIssuer(
        data=PID_DATA,
        private_key=PKEY,
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
        alg="ES256"
    )

    assert "eu.europa.ec.eudiw.pid.1" in msoi.hash_map
    assert msoi.hash_map["eu.europa.ec.eudiw.pid.1"]

    assert "eu.europa.ec.eudiw.pid.1" in msoi.disclosure_map
    assert msoi.disclosure_map["eu.europa.ec.eudiw.pid.1"]
    assert msoi.disclosure_map["eu.europa.ec.eudiw.pid.1"].values().__len__() == PID_DATA["eu.europa.ec.eudiw.pid.1"].values().__len__()

    mso = msoi.sign()

    Sign1Message.decode(mso.encode())

    # TODO: assertion about the content
    #  breakpoint()


def test_mdoc_issuer():
    mdoci = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
    )

    mdoc = mdoci.new(
        doctype="eu.europa.ec.eudiw.pid.1",
        data=PID_DATA,
        #devicekeyinfo=PKEY,  TODO
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
    )

    mdocp = MdocCbor()
    aa = cbor2.dumps(mdoc)
    mdocp.loads(aa)
    mdocp.verify()
    
    mdoci.dump()
    mdoci.dumps()
    
