import datetime
import os

COSEKEY_HAZMAT_CRV_MAP = {
    "secp256r1": "P_256",
    "secp384r1": "P_384",
    "secp521r1":  "P_521"
}

CRV_LEN_MAP = {
    "secp256r1": 32,
    "secp384r1": 48,
    "secp521r1": 66
}

PYMDOC_HASHALG: str = os.getenv('PYMDOC_HASHALG', "SHA-256")
PYMDOC_EXP_DELTA_HOURS: int = os.getenv('PYMDOC_EXP_DELTA_HOURS', 0)

HASHALG_MAP = {
    "SHA-256": "sha256",
    "SHA-512": "sha512",

}

DIGEST_SALT_LENGTH = 32

X509_DER_CERT = os.getenv('X509_DER_CERT', None)

# OR

X509_COUNTRY_NAME           = os.getenv('X509_COUNTRY_NAME', u"US")
X509_STATE_OR_PROVINCE_NAME = os.getenv('X509_STATE_OR_PROVINCE_NAME', u"California")
X509_LOCALITY_NAME          = os.getenv('X509_LOCALITY_NAME', u"San Francisco")
X509_ORGANIZATION_NAME      = os.getenv('X509_ORGANIZATION_NAME', u"My Company")
X509_COMMON_NAME            = os.getenv('X509_COMMON_NAME', u"mysite.com")

X509_NOT_VALID_BEFORE       = os.getenv('X509_NOT_VALID_BEFORE', datetime.datetime.now(datetime.UTC))
X509_NOT_VALID_AFTER_DAYS   = os.getenv('X509_NOT_VALID_AFTER_DAYS', 10)
X509_NOT_VALID_AFTER        = os.getenv(
    'X509_NOT_VALID_AFTER', 
    datetime.datetime.now(datetime.UTC) + datetime.timedelta(
        days=X509_NOT_VALID_AFTER_DAYS
    )
)

X509_SAN_URL = os.getenv(
    'X509_SAN_URL', u"https://credential-issuer.oidc-federation.online"
)

CBORTAGS_ATTR_MAP = {
    "birth_date": 1004,
    "expiry_date": 1004,
    "issue_date": 1004
}

