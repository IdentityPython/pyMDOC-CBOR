import cbor2
import cryptography
import logging

from pycose.keys import CoseKey, EC2Key
from pycose.messages import Sign1Message

from pymdoccbor.exceptions import (
    MsoX509ChainNotFound,
    UnsupportedMsoDataFormat
)
from pymdoccbor import settings
from pymdoccbor.tools import bytes2CoseSign1, cborlist2CoseSign1


logger = logging.getLogger("pymdoccbor")


class MsoVerifier:
    """
    MsoVerifier helper class to verify a mso

    Parameters
        data: CBOR TAG 24

    Example:
        MsoParser(mdoc['documents'][0]['issuerSigned']['issuerAuth'])

    Note
        The signature is contained in an untagged COSE_Sign1
        structure as defined in RFC 8152.
    """

    def __init__(self, data: cbor2.CBORTag) -> None:
        """
        Create a new MsoParser instance
        
        :param data: the data to verify
        :type data: cbor2.CBORTag
        
        :raises UnsupportedMsoDataFormat: if the data format is not supported
        """
        self._data = data
        # not used
        if isinstance(self._data, bytes):
            self.object: Sign1Message = bytes2CoseSign1(
                cbor2.dumps(cbor2.CBORTag(18, value=self._data)))
        elif isinstance(self._data, list):
            self.object: Sign1Message = cborlist2CoseSign1(self._data)
        else:
            raise UnsupportedMsoDataFormat(
                f"MsoParser only supports raw bytes and list, a {type(data)} was provided"
            )

        self.object.key: CoseKey | None = None
        self.public_key: cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey = None
        self.x509_certificates: list = []

    @property
    def payload_as_cbor(self) -> cbor2.CBORTag:
        """
        Return the decoded payload

        :return: the decoded payload
        :rtype: cbor2.CBORTag
        """
        return cbor2.loads(self.object.payload)

    @property
    def payload_as_raw(self) -> bytes:
        """
        Return the raw payload

        :return: the raw payload
        :rtype: bytes
        """
        return self.object.payload

    @property
    def payload_as_dict(self) -> dict:
        """
        Return the payload as dict
        """
        return cbor2.loads(
            cbor2.loads(self.object.payload).value
        )

    @property
    def raw_public_keys(self) -> bytes:
        """
        It returns the public key extract from x509 certificates
        looking to both phdr and uhdr

        :raises MsoX509ChainNotFound: if no valid x509 certificate is found
        
        :return: the raw public key
        :rtype: bytes
        """
        _mixed_heads = self.object.phdr.items() | self.object.uhdr.items()
        for h, v in _mixed_heads:
            if h.identifier == 33:
                return list(self.object.uhdr.values())

        raise MsoX509ChainNotFound(
            "I can't find any valid X509certs, identified by label number 33, "
            "in this MSO."
        )

    def attest_public_key(self) -> None:
        logger.warning(
            "TODO: in next releases. "
            "The certificate is to be considered as untrusted, this release "
            "doesn't validate x.509 certificate chain. See next releases and "
            "python certvalidator or cryptography for that."
        )

    def load_public_key(self) -> None:
        """
        Load the public key from the x509 certificate
        """

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
        """
        Verify the signature

        :return: True if valid, False otherwise
        :rtype: bool
        """
        if not self.object.key:
            self.load_public_key()

        return self.object.verify_signature()
