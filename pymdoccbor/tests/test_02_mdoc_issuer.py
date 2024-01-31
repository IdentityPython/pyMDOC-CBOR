import cbor2
import os

from pycose.messages import Sign1Message
from pycose.keys import EC2Key
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MdocCbor
from pymdoccbor.mso.issuer import MsoIssuer
from . pid_data import PID_DATA


PKEY = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})

def test_mso_writer():
    msoi = MsoIssuer(
        data=PID_DATA,
        private_key=PKEY
    )

    # TODO: assertion here about msow.hash_map and msow.disclosure_map

    mso = msoi.sign()

    Sign1Message.decode(mso.encode())

    # TODO: assertion about the content
    #  breakpoint()


def test_mdoc_issuer():
    mdoci = MdocCborIssuer(
        private_key=PKEY
    )

    mdoc = mdoci.new(
        doctype="eu.europa.ec.eudiw.pid.1",
        data=PID_DATA,
        devicekeyinfo=PKEY  # TODO
    )

    mdocp = MdocCbor()
    aa = cbor2.dumps(mdoc)
    mdocp.load(aa)
    mdocp.verify()
    
    mdoci.dump()
    mdoci.dumps()
    
    
