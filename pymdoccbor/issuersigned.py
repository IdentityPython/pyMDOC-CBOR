from . import IssuerAuth


class IssuerSigned:
    """
    IssuerAuth is a COSE_Sign1 ; The payload is the MobileSecurityObject, see ISO 18013-5 section 9.2.2.4 
    
    issuerAuth is a list of [
        cbor({1: -7}) # Protected Header, find -7 here https://datatracker.ietf.org/doc/html/rfc8152
        cbor({33: bytes}) # Unprotected Header containing X509 certificate
        cbor({24: bytes}) # Payload -> Mobile Security Object
        bytes # Signature
    ]
    """
    nameSpaces :dict = {}
    issuerAuth :IssuerAuth = None
