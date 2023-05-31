from typing import List

from pycose.messages.sign1message import Sign1Message

class IssuerAuth:
    """
    IssuerAuth is a COSE_Sign1 ; The payload is the MobileSecurityObject, see ISO 18013-5 section 9.2.2.4 
    
    A CBOR decoded issuerAuth is a list of [
        cbor({1: -7}) # Protected Header, find -7 here https://datatracker.ietf.org/doc/html/rfc8152
        cbor({33: bytes}) # Unprotected Header containing X509 certificate
        cbor({24: bytes}) # Payload -> Mobile Security Object
    ]
    """

    def parse(self, mso : Sign1Message) -> None:
        pass


    def read(self, mso_dict: dict) -> None:
        """
        Returns a CBOR Endoded tag 24
        """
    
    def verify_signature(self) -> bool:
        pass


    def load(self, mso :bytes):
        """
            loads a dumped COSE_Sign1
        """
        
        pass
    
    def dump(self) -> bool:
        pass
    
