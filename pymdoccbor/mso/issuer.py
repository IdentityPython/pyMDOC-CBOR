import cbor2
import datetime
import hashlib
import secrets
import uuid

from pycose.headers import Algorithm, KID
from pycose.keys import CoseKey, EC2Key
from pycose.messages import Sign1Message

from typing import Union

from pymdoccbor.exceptions import (
    MsoPrivateKeyRequired
)
from pymdoccbor import settings
from pymdoccbor.x509 import MsoX509Fabric
from pymdoccbor.tools import shuffle_dict


class MsoIssuer(MsoX509Fabric):
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
        elif private_key and isinstance(private_key, CoseKey):
            self.private_key = private_key
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
        
        _cert = settings.X509_DER_CERT or self.selfsigned_x509cert()
        
        mso = Sign1Message(
            phdr={
                Algorithm: self.private_key.alg,
                KID: self.private_key.kid,
                33: self.selfsigned_x509cert()
            },
            # TODO: x509 (cbor2.CBORTag(33)) and federation trust_chain support (cbor2.CBORTag(27?)) here
            # 33 means x509chain standing to rfc9360
            # in both protected and unprotected for interop purpose .. for now.
            uhdr={33: _cert},
            payload=cbor2.dumps(payload)
        )
        mso.key = self.private_key
        return mso
