import binascii 
import cbor2

from pycose.messages import Sign1Message


def bytes2CoseSign1(data :bytes) -> Sign1Message:
    """ 
        Gets bytes and return a COSE_Sign1 object
    """
    decoded = Sign1Message.decode(
        cbor2.dumps(
            cbor2.CBORTag(24, value=data)
        )
    )
    
    return decoded
