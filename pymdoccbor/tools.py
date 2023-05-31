import binascii 
import cbor2

from pycose.messages import Sign1Message


def bytes2CoseSign1(data :bytes) -> Sign1Message:
    
    #  binascii.unhexlify(data)
    
    decoded = Sign1Message.decode(
        cbor2.dumps(
            cbor2.CBORTag(18, value=data)
        )
    )
    
    return decoded
