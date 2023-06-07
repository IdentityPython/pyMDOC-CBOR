import os

COSEKEY_HAZMAT_CRV_MAP = {
    "secp256r1": "P_256"
}

CRV_LEN_MAP = {
    "secp256r1": 32,
}

PYMDOC_HASHALG :str = os.getenv('PYMDOC_HASHALG', "SHA-256")
PYMDOC_EXP_DELTA_HOURS :int = os.getenv('PYMDOC_EXP_DELTA_HOURS', 0)

HASHALG_MAP = {
    "SHA-256": "sha256",
    "SHA-512": "sha512",
    
}

DIGEST_SALT_LENGTH = 32

