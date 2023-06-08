import cbor2
import json
import random


from cbor2.tool import (
    DefaultEncoder,
    key_to_str
)
from pycose.messages import Sign1Message


def bytes2CoseSign1(data: bytes) -> Sign1Message:
    """
    Gets bytes and return a COSE_Sign1 object
    """
    decoded = Sign1Message.decode(cbor2.loads(data).value)

    return decoded


def cborlist2CoseSign1(data: list) -> Sign1Message:
    """ 
        Gets cbor2 decoded COSE Sign1 as a list and return a COSE_Sign1 object
    """
    decoded = Sign1Message.decode(
        cbor2.dumps(
            cbor2.CBORTag(18, value=data)
        )
    )

    return decoded


def pretty_print(cbor_loaded: dict):
    _obj = key_to_str(cbor_loaded)
    res = json.dumps(
        _obj,
        indent=(None, 4),
        cls=DefaultEncoder
    )
    print(res)


def shuffle_dict(d: dict):

    keys = list(d.keys())

    for i in range(random.randint(3, 27)):  # nosec: B311
        random.shuffle(keys)

    return dict([(key, d[key]) for key in keys])
