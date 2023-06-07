import cbor2
import cryptography
import datetime
import hashlib
import logging
import secrets
import uuid

from pycose.headers import Algorithm, KID
from pycose.keys import CoseKey, EC2Key
from pycose.messages import Sign1Message

from typing import Optional, Union

from . exceptions import (
    MsoX509ChainNotFound,
    MsoPrivateKeyRequired,
    UnsupportedMsoDataFormat
)
from . x509 import MsoX509Fabric
from . settings import COSEKEY_HAZMAT_CRV_MAP, CRV_LEN_MAP
from . tools import cborlist2CoseSign1, shuffle_dict
from . import settings


logger = logging.getLogger("pymdoccbor")


class MobileSecurityObject:
    """
    Notes
        The mDL public key is stored in the MSO, see ISO 18013-5 Section 9.2.2.4. 
        The mDL Reader assumes that the mDL is authentic 
        only if the authentication signature or MAC is correct.
    """


class MsoParser(MobileSecurityObject):
    """
    Parameters
        data: CBOR TAG 24

    Example:
        MsoParser(mdoc['documents'][0]['issuerSigned']['issuerAuth'])

    Note
        The signature is contained in an untagged COSE_Sign1 
        structure as defined in RFC 8152.
    """

    def __init__(self, data: cbor2.CBORTag):
        self._data = data

        # not used
        #  if isinstance(data, bytes):
        #  self.object: Sign1Message = bytes2CoseSign1(
        #  cbor2.dumps(cbor2.CBORTag(18, value=data)))
        #  el

        if isinstance(data, list):
            self.object: Sign1Message = cborlist2CoseSign1(self._data)
        else:
            raise UnsupportedMsoDataFormat(
                f"MsoParser only supports raw bytes and list, a {type(data)} was provided"
            )

        self.object.key: Optional[CoseKey, None] = None
        self.public_key: cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey = None
        self.x509_certificates: list = []

    @property
    def payload_as_cbor(self):
        """
        return the decoded payload
        """
        return cbor2.loads(self.object.payload)

    @property
    def payload_as_raw(self):
        return self.object.payload

    @property
    def payload_as_dict(self):
        return cbor2.loads(
            cbor2.loads(self.object.payload).value
        )

    @property
    def raw_public_keys(self) -> bytes:
        """
            it returns the public key extract from x509 certificates 
            looking to both phdr and uhdr
        """
        _mixed_heads = self.object.phdr.items() | self.object.uhdr.items()
        for h, v in _mixed_heads:
            if h.identifier == 33:
                return list(self.object.uhdr.values())

        raise MsoX509ChainNotFound(
            "I can't find any valid X509certs, identified by label number 33, "
            "in this MSO."
        )

    def attest_public_key(self):
        logger.warning(
            "TODO: in next releases. "
            "The certificate is to be considered as untrusted, this release "
            "doesn't validate x.509 certificate chain. See next releases and "
            "python certvalidator or cryptography for that."
        )

    def load_public_key(self):

        self.attest_public_key()

        for i in self.raw_public_keys:
            self.x509_certificates.append(
                cryptography.x509.load_der_x509_certificate(i)
            )

        self.public_key = self.x509_certificates[0].public_key()

        key = EC2Key(
            crv=COSEKEY_HAZMAT_CRV_MAP[self.public_key.curve.name],
            x=self.public_key.public_numbers().x.to_bytes(
                CRV_LEN_MAP[self.public_key.curve.name], 'big'
            )
        )
        self.object.key = key

    def verify_signature(self) -> bool:

        if not self.object.key:
            self.load_public_key()

        return self.object.verify_signature()


class MsoIssuer(MobileSecurityObject, MsoX509Fabric):
    """

    """

    def __init__(
        self,
        data: dict,
        private_key: Union[dict, CoseKey],
        digest_alg: str = settings.PYMDOC_HASHALG
    ):

        if private_key and isinstance(private_key, dict):
            self.private_key = CoseKey.from_dict(private_key)
            if not self.private_key.kid:
                self.private_key.kid = str(uuid.uuid4())
        else:
            raise MsoPrivateKeyRequired(
                "MSO Writer requires a valid private key"
            )

        self.public_key = EC2Key(
            crv=self.private_key.crv,
            x=self.private_key.x,
            y=self.private_key.y
        )

        self.data: dict = data
        self.hash_map: dict = {}
        self.disclosure_map: dict = {}
        self.digest_alg: str = digest_alg

        hashfunc = getattr(
            hashlib,
            settings.HASHALG_MAP[settings.PYMDOC_HASHALG]
        )

        digest_cnt = 0
        for ns, values in data.items():
            self.disclosure_map[ns] = {}
            self.hash_map[ns] = {}
            for k, v in shuffle_dict(values).items():

                _rnd_salt = secrets.token_bytes(settings.DIGEST_SALT_LENGTH)

                self.disclosure_map[ns][digest_cnt] = {
                    'digestID': digest_cnt,
                    'random': _rnd_salt,
                    'elementIdentifier': k,
                    'elementValue': v
                }

                self.hash_map[ns][digest_cnt] = hashfunc(
                    cbor2.dumps(
                        cbor2.CBORTag(
                            24,
                            value=cbor2.dumps(
                                self.disclosure_map[ns][digest_cnt]
                            )
                        )
                    )
                ).digest()

                digest_cnt += 1

    def format_datetime_repr(self, dt: datetime.datetime):
        return dt.isoformat().split('.')[0] + 'Z'

    def sign(
        self,
        device_key: Union[dict, None] = None,
        valid_from: Union[None, datetime.datetime] = None,
        doctype: str = None
    ) -> Sign1Message:
        """
            sign a mso and returns it
        """
        utcnow = datetime.datetime.utcnow()
        if settings.PYMDOC_EXP_DELTA_HOURS:
            exp = utcnow + datetime.timedelta(
                hours=settings.PYMDOC_EXP_DELTA_HOURS
            )
        else:
            # five years
            exp = utcnow + datetime.timedelta(hours=(24 * 365) * 5)

        payload = {
            'version': '1.0',
            'digestAlgorithm': settings.HASHALG_MAP[settings.PYMDOC_HASHALG],
            'valueDigests': self.hash_map,
            'deviceKeyInfo': {
                'deviceKey': device_key
            },
            'docType': doctype or list(self.hash_map)[0],
            'validityInfo': {
                'signed': cbor2.dumps(cbor2.CBORTag(0, self.format_datetime_repr(utcnow))),
                'validFrom': cbor2.dumps(cbor2.CBORTag(0, self.format_datetime_repr(valid_from or utcnow))),
                'validUntil': cbor2.dumps(cbor2.CBORTag(0, self.format_datetime_repr(exp)))
            }
        }

        mso = Sign1Message(
            phdr={
                Algorithm: self.private_key.alg,
                KID: self.private_key.kid,
                33: self.selfsigned_x509cert()
            },
            # TODO: x509 (cbor2.CBORTag(33)) and federation trust_chain support (cbor2.CBORTag(27?)) here
            # 33 means x509chain standing to rfc9360
            # in both protected and unprotected for interop purpose .. for now.
            uhdr={33: self.selfsigned_x509cert()},
            payload=cbor2.dumps(payload)
        )
        mso.key = self.private_key
        return mso
