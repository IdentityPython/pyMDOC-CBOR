import os

from pycose.messages import Sign1Message

from pymdoccbor.mso.issuer import MsoIssuer
from . pid_data import PID_DATA


PKEY = key_attribute_dict = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': os.urandom(32),
    'KID': b"demo-kid"
}


def test_mso_writer():
    msow = MsoIssuer(
        data=PID_DATA,
        private_key=PKEY
    )

    # TODO: assertion here about msow.hash_map and msow.disclosure_map

    mso = msow.sign()

    Sign1Message.decode(mso.encode())

    # TODO: assertion about the content
    #  breakpoint()
