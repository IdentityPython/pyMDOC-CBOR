import cbor2
import cryptography
import logging

from pycose.keys import CoseKey, EC2Key
from pycose.messages import Sign1Message

from typing import Optional

from pymdoccbor.exceptions import (
    MsoX509ChainNotFound,
    UnsupportedMsoDataFormat
)
from pymdoccbor import settings
from pymdoccbor.tools import bytes2CoseSign1, cborlist2CoseSign1


logger = logging.getLogger("pymdoccbor")


class MsoVerifier:
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
        if isinstance(data, bytes):
            self.object: Sign1Message = bytes2CoseSign1(
            cbor2.dumps(cbor2.CBORTag(18, value=data)))
        elif isinstance(data, list):
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
            crv=settings.COSEKEY_HAZMAT_CRV_MAP[self.public_key.curve.name],
            x=self.public_key.public_numbers().x.to_bytes(
                settings.CRV_LEN_MAP[self.public_key.curve.name], 'big'
            )
        )
        self.object.key = key

    def verify_signature(self) -> bool:

        if not self.object.key:
            self.load_public_key()

        return self.object.verify_signature()
