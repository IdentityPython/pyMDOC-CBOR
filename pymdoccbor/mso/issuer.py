# Modifications have been made to the original file (available at https://github.com/IdentityPython/pyMDOC-CBOR)
# All modifications Copyright (c) 2023 European Commission

# All modifications licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import cbor2
import datetime
import hashlib
import secrets
import uuid

from pycose.headers import Algorithm
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

from typing import Union


from pymdoccbor.exceptions import MsoPrivateKeyRequired
from pymdoccbor import settings
from pymdoccbor.x509 import MsoX509Fabric
from pymdoccbor.tools import shuffle_dict
from cryptography import x509
from cryptography.hazmat.primitives import serialization


from cbor_diag import *


class MsoIssuer(MsoX509Fabric):
    """ """

    def __init__(
        self,
        data: dict,
        validity: str,
        cert_path: str = None,
        key_label: str = None,
        user_pin: str = None,
        lib_path: str = None,
        slot_id: int = None,
        kid: str = None,
        alg: str = None,
        hsm: bool = False,
        private_key: Union[dict, CoseKey] = None,
        digest_alg: str = settings.PYMDOC_HASHALG,
    ):
        if not hsm:
            if private_key and isinstance(private_key, dict):
                self.private_key = CoseKey.from_dict(private_key)
                if not self.private_key.kid:
                    self.private_key.kid = str(uuid.uuid4())
            elif private_key and isinstance(private_key, CoseKey):
                self.private_key = private_key
            else:
                raise MsoPrivateKeyRequired("MSO Writer requires a valid private key")

        self.data: dict = data
        self.hash_map: dict = {}
        self.cert_path = cert_path
        self.disclosure_map: dict = {}
        self.digest_alg: str = digest_alg
        self.key_label = key_label
        self.user_pin = user_pin
        self.lib_path = lib_path
        self.slot_id = slot_id
        self.hsm = hsm
        self.alg = alg
        self.kid = kid
        self.validity = validity

        alg_map = {"ES256": "sha256", "ES384": "sha384", "ES512": "sha512"}

        hashfunc = getattr(hashlib, alg_map.get(self.alg))

        digest_cnt = 0
        for ns, values in data.items():
            self.disclosure_map[ns] = {}
            self.hash_map[ns] = {}
            for k, v in shuffle_dict(values).items():
                _rnd_salt = secrets.token_bytes(settings.DIGEST_SALT_LENGTH)

                _value_cbortag = settings.CBORTAGS_ATTR_MAP.get(k, None)

                if _value_cbortag:
                    v = cbor2.CBORTag(_value_cbortag, value=v)
                    # print("\n-----\n K,V ", k, "\n", v)

                if k == "driving_privileges":
                    for item in v:
                        for k2, v2 in item.items():
                            _value_cbortag = settings.CBORTAGS_ATTR_MAP.get(k2, None)
                            if _value_cbortag:
                                item[k2] = cbor2.CBORTag(_value_cbortag, value=v2)

                self.disclosure_map[ns][digest_cnt] = cbor2.CBORTag(
                    24,
                    value=cbor2.dumps(
                        {
                            "digestID": digest_cnt,
                            "random": _rnd_salt,
                            "elementIdentifier": k,
                            "elementValue": v,
                        },
                        canonical=True,
                    ),
                )

                self.hash_map[ns][digest_cnt] = hashfunc(
                    cbor2.dumps(self.disclosure_map[ns][digest_cnt], canonical=True)
                ).digest()

                digest_cnt += 1

    def format_datetime_repr(self, dt: datetime.datetime):
        return dt.isoformat().split(".")[0] + "Z"

    def sign(
        self,
        device_key: Union[dict, None] = None,
        valid_from: Union[None, datetime.datetime] = None,
        doctype: str = None,
    ) -> Sign1Message:
        """
        sign a mso and returns itprivate_key
        """
        utcnow = datetime.datetime.utcnow()
        valid_from = datetime.datetime.strptime(
            self.validity["issuance_date"], "%Y-%m-%d"
        )
        if settings.PYMDOC_EXP_DELTA_HOURS:
            exp = utcnow + datetime.timedelta(hours=settings.PYMDOC_EXP_DELTA_HOURS)
        else:
            # five years
            exp = datetime.datetime.strptime(self.validity["expiry_date"], "%Y-%m-%d")
            # exp = utcnow + datetime.timedelta(hours=(24 * 365) * 5)

        if utcnow > valid_from:
            valid_from = utcnow

        alg_map = {"ES256": "SHA-256", "ES384": "SHA-384", "ES512": "SHA-512"}

        payload = {
            "docType": doctype or list(self.hash_map)[0],
            "version": "1.0",
            "validityInfo": {
                "signed": cbor2.CBORTag(0, self.format_datetime_repr(utcnow)),
                "validFrom": cbor2.CBORTag(
                    0, self.format_datetime_repr(valid_from or utcnow)
                ),
                "validUntil": cbor2.CBORTag(0, self.format_datetime_repr(exp)),
            },
            "valueDigests": self.hash_map,
            "deviceKeyInfo": {
                "deviceKey": device_key,
            },
            "digestAlgorithm": alg_map.get(self.alg),
        }

        if self.cert_path:
            # Load the DER certificate file
            with open(self.cert_path, "rb") as file:
                certificate = file.read()

            cert = x509.load_der_x509_certificate(certificate)

            _cert = cert.public_bytes(getattr(serialization.Encoding, "DER"))
        else:
            _cert = self.selfsigned_x509cert()

        if self.hsm:
            # print("payload diganostic notation: \n",cbor2diag(cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(payload)))))

            mso = Sign1Message(
                phdr={
                    Algorithm: self.alg,
                    # 33: _cert
                },
                # TODO: x509 (cbor2.CBORTag(33)) and federation trust_chain support (cbor2.CBORTag(27?)) here
                # 33 means x509chain standing to rfc9360
                # in both protected and unprotected for interop purpose .. for now.
                uhdr={33: _cert},
                payload=cbor2.dumps(
                    cbor2.CBORTag(24, cbor2.dumps(payload, canonical=True)),
                    canonical=True,
                ),
            )

        else:
            # print("payload diganostic notation: \n", cbor2diag(cbor2.dumps(cbor2.CBORTag(24,cbor2.dumps(payload)))))

            mso = Sign1Message(
                phdr={
                    Algorithm: self.private_key.alg,
                    # KID: self.private_key.kid,
                    # 33: _cert
                },
                # TODO: x509 (cbor2.CBORTag(33)) and federation trust_chain support (cbor2.CBORTag(27?)) here
                # 33 means x509chain standing to rfc9360
                # in both protected and unprotected for interop purpose .. for now.
                uhdr={33: _cert},
                payload=cbor2.dumps(
                    cbor2.CBORTag(24, cbor2.dumps(payload, canonical=True)),
                    canonical=True,
                ),
            )

            mso.key = self.private_key

        return mso
