import os

COSEKEY_HAZMAT_CRV_MAP = {
    "secp256r1": "P_256",
    "secp384r1": "P_384",
    "secp521r1":  "P_521"
}

CRV_LEN_MAP = {
    "secp256r1": 32,
}

PYMDOC_HASHALG: str = os.getenv("PYMDOC_HASHALG", "SHA-256")
PYMDOC_EXP_DELTA_HOURS: int = os.getenv("PYMDOC_EXP_DELTA_HOURS", 0)

HASHALG_MAP = {
    "SHA-256": "sha256",
    "SHA-512": "sha512",
}

DIGEST_SALT_LENGTH = 32

X509_DER_CERT = os.getenv("X509_DER_CERT", None)

CBORTAGS_ATTR_MAP = {
    "birth_date": 1004,
    "expiry_date": 1004,
    "issue_date": 1004,
    "issuance_date": 1004,
}
