from typing import List

from . issuersigned import IssuerSigned


class MobileDocument:

    docType :str = 'org.iso.18013.5.1.mDL'
    issuerSigned :List[IssuerSigned] = []


class MdocEnvelope:
    
    version :str = '1.0'
    documents :List[MobileDocument] = [] 
    status :int = 0
    
