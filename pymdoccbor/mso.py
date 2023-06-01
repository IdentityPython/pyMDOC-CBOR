import binascii
import cbor2
import cryptography
import logging

from pycose.keys import CoseKey, EC2Key
from pycose.messages import Sign1Message

from typing import Optional, Union
from . tools import bytes2CoseSign1


COSEKEY_HAZMAT_CRV_MAP = {
    "secp256r1": "P_256"
}
CRV_LEN_MAP = {
    "secp256r1": 32,
}

logger = logging.getLogger("mso")


class MobileSecurityObject:
    """
    Notes
        The mDL public key is stored in the MSO, see ISO 18013-5 Section 9.2.2.4. 
        The mDL Reader assumes that the mDL is authentic 
        only if the authentication signature or MAC is correct.
    """

    pass
    
    
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
        
        self.object :Sign1Message = bytes2CoseSign1(self._data)
        self.object.key :Optional[CoseKey, None]  = None
        self.public_key :cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey = None
        self.x509_certificates :list  = []
        
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
        return list(self.object.uhdr.values())
    
    def load_public_key(self):
        
        logger.warning(
            "TODO: in next releases. "
            "The certificate is to be considered as untrusted, this release "
            "doesn't validate x.509 certificate chain. See next releases and "
            "python certvalidator or cryptography for that"
        )
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


class MsoWriter(MobileSecurityObject):
    """
        
    """
    pass
