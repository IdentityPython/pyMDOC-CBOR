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

import base64
import binascii
import cbor2
import logging
from cryptography.hazmat.primitives import serialization
from pycose.keys import CoseKey
from typing import Union

from pymdoccbor.mso.issuer import MsoIssuer

from cbor_diag import *


logger = logging.getLogger("pymdoccbor")


class MdocCborIssuer:
    def __init__(
        self,
        key_label: str = None,
        user_pin: str = None,
        lib_path: str = None,
        slot_id: int = None,
        hsm: bool = False,
        alg: str = None,
        kid: str = None,
        private_key: Union[dict, CoseKey] = {},
    ):
        self.version: str = "1.0"
        self.status: int = 0
        if private_key and isinstance(private_key, dict):
            self.private_key = CoseKey.from_dict(private_key)

        self.signed: dict = {}
        self.key_label = key_label
        self.user_pin = user_pin
        self.lib_path = lib_path
        self.slot_id = slot_id
        self.hsm = hsm
        self.alg = alg
        self.kid = kid

    def new(
        self,
        data: dict,
        doctype: str,
        validity: dict = None,
        devicekeyinfo: Union[dict, CoseKey, str] = None,
        cert_path: str = None,
    ):
        """
        create a new mdoc with signed mso
        """
        if isinstance(devicekeyinfo, dict):
            devicekeyinfo = CoseKey.from_dict(devicekeyinfo)
        if isinstance(devicekeyinfo, str):
            device_key_bytes = base64.urlsafe_b64decode(devicekeyinfo.encode("utf-8"))
            public_key = serialization.load_pem_public_key(device_key_bytes)
            curve_name = public_key.curve.name
            curve_map = {
                "secp256r1": 1,  # NIST P-256
                "secp384r1": 2,  # NIST P-384
                "secp521r1": 3,  # NIST P-521
                "brainpoolP256r1": 8,  # Brainpool P-256
                "brainpoolP384r1": 9,  # Brainpool P-384
                "brainpoolP512r1": 10,  # Brainpool P-512
                # Add more curve mappings as needed
            }
            curve_identifier = curve_map.get(curve_name)

            # Extract the x and y coordinates from the public key
            x = public_key.public_numbers().x.to_bytes(
                (public_key.public_numbers().x.bit_length() + 7)
                // 8,  # Number of bytes needed
                "big",  # Byte order
            )

            y = public_key.public_numbers().y.to_bytes(
                (public_key.public_numbers().y.bit_length() + 7)
                // 8,  # Number of bytes needed
                "big",  # Byte order
            )

            devicekeyinfo = {
                1: 2,
                -1: curve_identifier,
                -2: x,
                -3: y,
            }

        else:
            devicekeyinfo: CoseKey = devicekeyinfo

        if self.hsm:
            msoi = MsoIssuer(
                data=data,
                cert_path=cert_path,
                hsm=self.hsm,
                key_label=self.key_label,
                user_pin=self.user_pin,
                lib_path=self.lib_path,
                slot_id=self.slot_id,
                alg=self.alg,
                kid=self.kid,
                validity=validity,
            )

        else:
            msoi = MsoIssuer(
                data=data,
                private_key=self.private_key,
                alg=self.alg,
                cert_path=cert_path,
                validity=validity,
            )

        mso = msoi.sign(doctype=doctype, device_key=devicekeyinfo)

        mso_cbor = mso.encode(
            tag=False,
            hsm=self.hsm,
            key_label=self.key_label,
            user_pin=self.user_pin,
            lib_path=self.lib_path,
            slot_id=self.slot_id,
        )

        # TODO: for now just a single document, it would be trivial having
        # also multiple but for now I don't have use cases for this
        res = {
            # "version": self.version,
            # "documents": [
            # {
            # "docType": doctype,  # 'org.iso.18013.5.1.mDL'
            # "issuerSigned": {
            "nameSpaces": {
                ns: [v for k, v in dgst.items()]
                for ns, dgst in msoi.disclosure_map.items()
            },
            "issuerAuth": cbor2.decoder.loads(mso_cbor),
            # },
            # }
            # ],
            # "status": self.status,
        }

        # print("mso diganostic notation: \n", cbor2diag(mso_cbor))

        self.signed = res
        return self.signed

    def dump(self):
        """
        returns bytes
        """
        return cbor2.dumps(self.signed, canonical=True)

    def dumps(self):
        """
        returns AF binary repr
        """
        return binascii.hexlify(cbor2.dumps(self.signed, canonical=True))
