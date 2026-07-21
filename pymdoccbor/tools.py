# Aligns with https://github.com/eu-digital-identity-wallet/pyMDOC-CBOR
import json
import random
from collections.abc import Mapping, Sequence
from typing import Any, Union

import cbor2
from cbor2.tool import DefaultEncoder, key_to_str
from pycose.messages import Sign1Message


def thaw_cbor(obj: Any) -> Any:
    """
    Convert cbor2 6.x immutable decode results into mutable structures.

    cbor2 >= 6 returns tuple for arrays and frozendict for maps. pycose 1.x
    requires a mutable list (it uses .pop) and a plain dict for COSE headers.
    """
    if isinstance(obj, cbor2.CBORTag):
        return cbor2.CBORTag(obj.tag, thaw_cbor(obj.value))
    if isinstance(obj, Mapping):
        return {thaw_cbor(k): thaw_cbor(v) for k, v in obj.items()}
    if isinstance(obj, tuple):
        return [thaw_cbor(item) for item in obj]
    if isinstance(obj, list):
        return [thaw_cbor(item) for item in obj]
    return obj


def _cose_sign1_from_obj(cose_obj: Any) -> Sign1Message:
    """Build a Sign1Message from a decoded COSE_Sign1 array (list or tuple)."""
    cose_obj = thaw_cbor(cose_obj)
    if not isinstance(cose_obj, list):
        raise TypeError("Bytes cannot be decoded as COSE message")
    return Sign1Message.from_cose_obj(cose_obj, True)


def bytes2CoseSign1(data: bytes) -> Sign1Message:
    """
    Gets bytes and return a COSE_Sign1 object

    :param data: bytes: the COSE Sign1 as bytes (optionally CBOR-tagged 18)
    :return: Sign1Message: the COSE Sign1 object
    """
    loaded = cbor2.loads(data)
    if isinstance(loaded, cbor2.CBORTag):
        cose_obj = loaded.value
    else:
        cose_obj = loaded

    # Tag value may itself be the encoded array as bytes
    if isinstance(cose_obj, (bytes, bytearray)):
        cose_obj = cbor2.loads(cose_obj)

    return _cose_sign1_from_obj(cose_obj)


def cborlist2CoseSign1(data: Union[list, tuple, Sequence]) -> Sign1Message:
    """
    Gets cbor2 decoded COSE Sign1 as a list/tuple and return a COSE_Sign1 object

    :param data: list | tuple: the COSE Sign1 as a decoded array
    :return: Sign1Message: the COSE Sign1 object
    """
    return _cose_sign1_from_obj(data)


def pretty_print(cbor_loaded: dict) -> None:
    """"
    Pretty print a CBOR object

    :param cbor_loaded: dict: the CBOR object
    """
    _obj = key_to_str(cbor_loaded)
    res = json.dumps(
        _obj,
        indent=(None, 4),
        cls=DefaultEncoder
    )
    print(res)


def shuffle_dict(d: dict) -> dict:
    """
    Shuffle a dictionary

    :param d: dict: the dictionary to shuffle
    :return: dict: the shuffled dictionary
    """

    keys = list(d.keys())

    for i in range(random.randint(3, 27)):  # nosec: B311
        random.shuffle(keys)

    return dict([(key, d[key]) for key in keys])
