import datetime
import hashlib
import logging
import secrets
import uuid
from typing import Union

import cbor2
from cbor_diag import cbor2diag
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from pycose.headers import Algorithm
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

from pymdoccbor import settings
from pymdoccbor.exceptions import MsoPrivateKeyRequired
from pymdoccbor.tools import shuffle_dict
from pymdoccbor.x509 import selfsigned_x509cert

logger = logging.getLogger("pymdoccbor")


class MsoIssuer:
    """
    MsoIssuer helper class to create a new mso
    """

    def __init__(
        self,
        data: dict,
        validity: dict,
        cert_path: str | None = None,
        key_label: str | None = None,
        user_pin: str | None = None,
        lib_path: str | None = None,
        slot_id: int | None = None,
        kid: str | None = None,
        alg: str | None = None,
        hsm: bool | None = False,
        private_key: dict | CoseKey | None = None,
        digest_alg: str | None = settings.PYMDOC_HASHALG,
        revocation: dict | None = None,
        cert_info: dict | None = None,
    ) -> None:
        """
        Initialize a new MsoIssuer

        :param data: dict: the data to sign
        :param validity: validity: the validity info of the mso
        :param cert_path: str: the path to the certificate
        :param key_label: str: key label
        :param user_pin: str: user pin
        :param lib_path: str: path to the library cryptographic library
        :param slot_id: int: slot id
        :param kid: str: key id
        :param alg: str: hashig algorithm
        :param hsm: bool: hardware security module
        :param private_key: Union[dict, CoseKey]: the signing key
        :param digest_alg: str: the digest algorithm
        :param revocation: dict: revocation dict (may include status_list, identifier_list)
        """

        if private_key:
            if isinstance(private_key, dict):
                self.private_key = CoseKey.from_dict(private_key)
                if not self.private_key.kid:
                    self.private_key.kid = str(uuid.uuid4())
            elif isinstance(private_key, CoseKey):
                self.private_key = private_key
            else:
                raise ValueError("private_key must be a dict or CoseKey object")
        else:
            if not hsm:
                raise MsoPrivateKeyRequired("MSO Writer requires a valid private key")

        if not validity:
            raise ValueError("validity must be present")

        if not alg:
            raise ValueError("alg must be present")

        self.data: dict = data
        self.hash_map: dict = {}
        self.disclosure_map: dict = {}
        self.digest_alg = digest_alg
        self.key_label = key_label
        self.user_pin = user_pin
        self.lib_path = lib_path
        self.slot_id = slot_id
        self.hsm = hsm
        self.alg = alg
        self.kid = kid
        self.validity = validity
        self.revocation = revocation

        self.cert_path = cert_path
        self.cert_info = cert_info

        if not self.cert_path and (not self.cert_info or not self.private_key):
            raise ValueError(
                "cert_path or cert_info with a private key must be provided to properly insert a certificate"
            )

        alg_map = {"ES256": "sha256", "ES384": "sha384", "ES512": "sha512"}

        if self.alg not in alg_map:
            raise ValueError(f"Unsupported algorithm: {self.alg}")

        hashfunc = getattr(hashlib, alg_map[self.alg])

        digest_cnt = 0
        for ns, values in data.items():
            self.disclosure_map[ns] = {}
            self.hash_map[ns] = {}
            for k, v in shuffle_dict(values).items():
                _rnd_salt = secrets.token_bytes(settings.DIGEST_SALT_LENGTH)

                _value_cbortag = settings.CBORTAGS_ATTR_MAP.get(k, None)

                if _value_cbortag:
                    v = cbor2.CBORTag(_value_cbortag, value=v)

                if isinstance(v, dict):
                    for k2, v2 in v.items():
                        _value_cbortag = settings.CBORTAGS_ATTR_MAP.get(k2, None)
                        if _value_cbortag:
                            v[k2] = cbor2.CBORTag(_value_cbortag, value=v2)

                if isinstance(v, list) and k != "nationality":
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

    def format_datetime_repr(self, dt: datetime.datetime) -> str:
        """
        Format a datetime object to a string

        :param dt: datetime.datetime: the datetime object
        :return: str: the formatted string
        """
        return dt.isoformat().split(".")[0] + "Z"

    def sign(
        self,
        device_key: dict | None = None,
        valid_from: datetime.datetime | None = None,
        doctype: str | None = None,
    ) -> Sign1Message:
        """
        Sign a mso and returns it

        :param device_key: Union[dict, None]: the device key
        :param valid_from: Union[None, datetime.datetime]: the valid from date
        :param doctype: str: the document type

        :return: Sign1Message: the signed mso
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
            "digestAlgorithm": alg_map.get(self.alg)
        }
        if self.revocation is not None:
            payload.update({"status": self.revocation})

        if self.cert_path:
            # Try to load the certificate file
            with open(self.cert_path, "rb") as file:
                certificate = file.read()
            _parsed_cert: Union[Certificate, None] = None
            try:
                _parsed_cert = x509.load_pem_x509_certificate(certificate)
            except Exception:
                logger.error(
                    f"Certificate at {self.cert_path} could not be loaded as PEM, trying DER"
                )

            if not _parsed_cert:
                try:
                    _parsed_cert = x509.load_der_x509_certificate(certificate)
                except Exception:
                    _err_msg = (
                        f"Certificate at {self.cert_path} could not be loaded as DER"
                    )
                    logger.error(_err_msg)

            if _parsed_cert:
                cert = _parsed_cert
            else:
                raise Exception(f"Certificate at {self.cert_path} failed parse")
            _cert = cert.public_bytes(getattr(serialization.Encoding, "DER"))
        else:
            if not self.cert_info:
                raise ValueError("cert_info must be provided if cert_path is not set")

            logger.warning(
                "A self-signed certificate will be created using the provided "
                "cert_info but this is not recommended for production use."
            )

            _cert = selfsigned_x509cert(self.cert_info, self.private_key)

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
            logger.debug(
                "payload diagnostic notation: %s",
                cbor2diag(cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(payload)))),
            )

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
