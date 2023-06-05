import binascii
import cbor2
import logging

from typing import List

from . exceptions import InvalidMdoc
from . issuersigned import IssuerSigned

logger = logging.getLogger('pymdoccbor')


class MobileDocument:
    _states = {
        True: "valid",
        False: "failed",
    }
    
    def __init__(self, docType :str, issuerSigned : dict, deviceSigned :dict = {}):
        self.doctype :str = docType # eg: 'org.iso.18013.5.1.mDL'
        self.issuersigned :List[IssuerSigned] = IssuerSigned(**issuerSigned)
        self.is_valid = False
        
        # TODO
        self.devicesigned :dict = deviceSigned
        
        
    def dump(self) -> dict:
        return {
            'docType': self.doctype,
            'issuerSigned': self.issuersigned.dump()
        }
    
    def dumps(self) -> dict:
        return cbor2.dumps(
            cbor2.CBORTag(24, value = {
                    'docType': self.doctype,
                    'issuerSigned': self.issuersigned.dumps()
                }
            )
        )
    
    def verify(self) -> bool:
        self.is_valid = self.issuersigned.issuer_auth.verify_signature()
        return self.is_valid
    
    def __repr__(self):
        return f"{self.__module__}.{self.__class__.__name__} [{self._states[self.is_valid]}]"

class MdocCbor:
    
    version :str = '1.0'
    documents :List[MobileDocument] = [] 
    status :int = 0
        
    def __init__(self):
        self.data_as_bytes :bytes = b""
        self.data_as_cbor_dict :dict = {}
        
        self.documents :List[MobileDocument] = []
        self.documents_invalid : list = []

    def loads(self, data :str):
        """
        data is a AF BINARY 
        """
        if isinstance(data, bytes):
            data = binascii.hexlify(data)
        
        self.data_as_bytes = binascii.unhexlify(data)
        self.data_as_cbor_dict = cbor2.loads(self.data_as_bytes)

    def dump(self):
        return self.data_as_bytes

    def dumps(self) -> str:
        """
            returns AF binary string representation
        """
        return binascii.hexlify(self.data_as_bytes)

    @property
    def data_as_string(self):
        return self.dumps()

    def verify(self):
        
        cdict = self.data_as_cbor_dict
        
        for i in ('version', 'documents'):
            if i not in cdict:
                raise InvalidMdoc(
                    f"Mdoc is invalid since it doesn't contain the '{i}' element"
                )
        
        doc_cnt = 1
        for doc in cdict['documents']:
            mso = MobileDocument(**doc)
            
            try:
                mso.verify()
            except Exception as e:
                logger.error(
                    f"COSE Sign1 validation failed to the document number #{doc_cnt}. "
                    f"Then it is appended to self.documents_invalid: {e}"
                )
                self.documents_invalid.append(doc)
                doc_cnt += 1
                continue
                
            self.documents.append(mso)
            doc_cnt +=1
            
        
    
    
    
