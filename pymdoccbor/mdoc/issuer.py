import base64
import binascii
import logging
from datetime import datetime, timezone
from typing import Union

import cbor2
from cbor_diag import cbor2diag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pycose.keys import CoseKey, EC2Key

from pymdoccbor.mdoc.exceptions import InvalidStatusDescriptor
from pymdoccbor.mso.issuer import MsoIssuer

logger = logging.getLogger("pymdoccbor")


class MdocCborIssuer:
    """
    MdocCborIssuer helper class to create a new mdoc
    """

    def __init__(
        self,
        key_label: str | None = None,
        user_pin: str | None = None,
        lib_path: str | None = None,
        slot_id: int | None = None,
        hsm: bool = False,
        alg: str | None = None,
        kid: str | None = None,
        private_key: Union[dict, CoseKey] = {},
        cert_info: dict | None = None,
    ):
        """
        Initialize a new MdocCborIssuer

        :param key_label: str: key label
        :param user_pin: str: user pin
        :param lib_path: str: path to the library cryptographic library
        :param slot_id: int: slot id
        :param hsm: bool: hardware security module
        :param alg: str: hashig algorithm
        :param kid: str: key id
        :param private_key: Union[dict, CoseKey]: private key
        """
        self.version: str = "1.0"
        self.status: int = 0

        if private_key:
            if isinstance(private_key, dict):
                self.private_key = CoseKey.from_dict(private_key)
            elif isinstance(private_key, EC2Key):
                ec2_encoded = private_key.encode()
                ec2_decoded = CoseKey.decode(ec2_encoded)
                self.private_key = ec2_decoded
            elif isinstance(private_key, CoseKey):
                self.private_key = private_key
            else:
                raise ValueError("private_key must be a dict or CoseKey object")

        self.signed: dict = {}
        self.key_label = key_label
        self.user_pin = user_pin
        self.lib_path = lib_path
        self.slot_id = slot_id
        self.hsm = hsm
        self.alg = alg
        self.kid = kid
        self.cert_info = cert_info

    def new(
        self,
        data: dict,
        doctype: str,
        validity: dict | None = None,
        devicekeyinfo: dict | CoseKey | str | None = None,
        cert_path: str | None = None,
        revocation: dict | None = None,
        status: dict | None = None
    ) -> dict:
        """
        create a new mdoc with signed mso

        :param data: dict: data to be signed
        :param doctype: str: document type
        :param validity: dict: validity info
        :param devicekeyinfo: Union[dict, CoseKey, str]: device key info
        :param cert_path: str: path to the certificate
        :param revocation: dict: revocation status dict it may include status_list and identifier_list keys
        :param status: dict: status dict with uri and idx per draft-ietf-oauth-status-list
        :return: dict: signed mdoc
        """
        if isinstance(devicekeyinfo, dict):
            devicekeyinfoCoseKeyObject = CoseKey.from_dict(devicekeyinfo)
            if devicekeyinfoCoseKeyObject.kty.identifier == 2:  # EC2Key
                devicekeyinfo = {
                    1: devicekeyinfoCoseKeyObject.kty.identifier,
                    -1: devicekeyinfoCoseKeyObject.crv.identifier,
                    -2: devicekeyinfoCoseKeyObject.x,
                    -3: devicekeyinfoCoseKeyObject.y,
                }
            elif devicekeyinfoCoseKeyObject.kty.identifier == 1:  # OKPKey
                devicekeyinfo = {
                    1: devicekeyinfoCoseKeyObject.kty.identifier,
                    -1: devicekeyinfoCoseKeyObject.crv.identifier,
                    -2: devicekeyinfoCoseKeyObject.x,
                }
            elif devicekeyinfoCoseKeyObject.kty.identifier == 3:  # RSAKey
                devicekeyinfo = {
                    1: devicekeyinfoCoseKeyObject.kty.identifier,
                    -1: devicekeyinfoCoseKeyObject.n,
                    -2: devicekeyinfoCoseKeyObject.e,
                }
            else:
                raise TypeError("Unsupported key type in devicekeyinfo")
        if isinstance(devicekeyinfo, str):
            device_key_bytes = base64.urlsafe_b64decode(devicekeyinfo.encode("utf-8"))
            public_key = serialization.load_pem_public_key(device_key_bytes)

            if isinstance(public_key, EllipticCurvePublicKey):
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
            elif isinstance(public_key, Ed25519PublicKey):
                devicekeyinfo = {
                    1: 1,  # OKPKey
                    -1: "Ed25519",  # Curve identifier for Ed25519
                    -2: public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    ),
                }
            elif isinstance(public_key, RSAPublicKey):
                devicekeyinfo = {
                    1: 3,  # RSAKey
                    -1: public_key.public_numbers().n.to_bytes(
                        (public_key.public_numbers().n.bit_length() + 7) // 8, "big"
                    ),
                    -2: public_key.public_numbers().e.to_bytes(
                        (public_key.public_numbers().e.bit_length() + 7) // 8, "big"
                    )
                }
            else:
                raise TypeError("Loaded public key is not an EllipticCurvePublicKey")

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
                revocation=revocation,
                cert_info=self.cert_info
            )

        else:
            msoi = MsoIssuer(
                data=data,
                private_key=self.private_key,
                alg=self.alg,
                cert_path=cert_path,
                validity=validity,
                revocation=revocation,
                cert_info=self.cert_info
            )

        mso = msoi.sign(
            doctype=doctype,
            device_key=devicekeyinfo,
            valid_from=datetime.now(timezone.utc)
        )

        mso_cbor = mso.encode(
            tag=False,
            hsm=self.hsm,
            key_label=self.key_label,
            user_pin=self.user_pin,
            lib_path=self.lib_path,
            slot_id=self.slot_id,
        )

        res = {
            "version": self.version,
            "documents": [
                {
                    "docType": doctype,  # 'org.iso.18013.5.1.mDL'
                    "issuerSigned": {
                        "nameSpaces": {
                            ns: [v for k, v in dgst.items()]
                            for ns, dgst in msoi.disclosure_map.items()
                        },
                        "issuerAuth": cbor2.loads(mso_cbor)
                    },
                }
            ],
            "status": self.status,
        }

        if status:
            if "status_list" not in status:
                raise InvalidStatusDescriptor("status_list is required")

            if "uri" not in status["status_list"]:
                raise InvalidStatusDescriptor("uri is required")
            if "idx" not in status["status_list"]:
                raise InvalidStatusDescriptor("idx is required")

            res["status"] = status

        logger.debug(f"MSO diagnostic notation: {cbor2diag(mso_cbor)}")

        self.signed = res
        return self.signed

    def dump(self) -> bytes:
        """
        Returns the CBOR representation of the signed mdoc

        :return: bytes: CBOR representation of the signed mdoc
        """
        return cbor2.dumps(self.signed, canonical=True)

    def dumps(self) -> bytes:
        """
        Returns the AF binary representation of the signed mdoc

        :return: bytes: AF binary representation of the signed mdoc
        """
        return binascii.hexlify(cbor2.dumps(self.signed, canonical=True))
