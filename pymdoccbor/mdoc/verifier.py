import binascii
import cbor2
import logging

from typing import List

from pymdoccbor.exceptions import InvalidMdoc
from pymdoccbor.mdoc.issuersigned import IssuerSigned
from pymdoccbor.mdoc.exceptions import NoDocumentTypeProvided, NoSignedDocumentProvided

logger = logging.getLogger('pymdoccbor')


class MobileDocument:
    """
    MobileDocument helper class to verify a mdoc
    """

    _states = {
        True: "valid",
        False: "failed",
    }

    def __init__(self, docType: str, issuerSigned: dict, deviceSigned: dict = {}):
        """
        Create a new MobileDocument instance

        :param docType: the document type
        :type docType: str
        :param issuerSigned: the issuer signed data
        :type issuerSigned: dict
        :param deviceSigned: the device signed data
        :type deviceSigned: dict

        :raises NoDocumentTypeProvided: if no document type is provided
        :raises NoSignedDocumentProvided: if no signed document is provided
        """

        if not docType:
            raise NoDocumentTypeProvided("You must provide a document type")
        
        if not issuerSigned:
            raise NoSignedDocumentProvided("You must provide a signed document")
        
        self.doctype: str = docType  # eg: 'org.iso.18013.5.1.mDL'
        self.issuersigned: IssuerSigned = IssuerSigned(**issuerSigned)
        self.is_valid = False

        # TODO
        self.devicesigned: dict = deviceSigned

    def dump(self) -> dict:
        """
        Returns a dict representation of the document

        :return: the document as dict
        :rtype: dict
        """

        return {
            'docType': self.doctype,
            'issuerSigned': self.issuersigned.dump()
        }
    
    def dumps(self) -> str:
        """
        Returns an AF binary repr of the document

        :return: the document as AF binary
        :rtype: str
        """
        return binascii.hexlify(self.dump())
    
    def dump(self) -> bytes:
        """
        Returns a CBOR repr of the document

        :return: the document as CBOR
        :rtype: bytes
        """
        return cbor2.dumps(
            cbor2.CBORTag(24, value={
                'docType': self.doctype,
                'issuerSigned': self.issuersigned.dumps()
            })
        )

    def verify(self) -> bool:
        """
        Verify the document signature

        :return: True if valid, False otherwise
        :rtype: bool
        """

        self.is_valid = self.issuersigned.issuer_auth.verify_signature()
        return self.is_valid

    def __repr__(self):
        return f"{self.__module__}.{self.__class__.__name__} [{self._states[self.is_valid]}]"


class MdocCbor:

    def __init__(self):
        self.data_as_bytes: bytes = b""
        self.data_as_cbor_dict: dict = {}

        self.documents: List[MobileDocument] = []
        self.documents_invalid: list = []

    def load(self, data: bytes):
        data = binascii.hexlify(data)
        return self.loads(data)

    def loads(self, data: str):
        """
        data is a AF BINARY
        """
        self.data_as_bytes = binascii.unhexlify(data)
        self.data_as_cbor_dict = cbor2.loads(self.data_as_bytes)

    def dump(self) -> bytes:
        """
            returns bytes
        """
        return self.data_as_bytes

    def dumps(self) -> str:
        """
            returns AF binary string representation
        """
        return binascii.hexlify(self.data_as_bytes)

    @property
    def data_as_string(self) -> str:
        return self.dumps().decode()

    def verify(self) -> bool:
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
                if mso.verify():
                    self.documents.append(mso)
                else:
                    self.documents_invalid.append(mso)

            except Exception as e:
                logger.error(
                    f"COSE Sign1 validation failed to the document number #{doc_cnt}. "
                    f"Then it is appended to self.documents_invalid: {e}"
                )
                self.documents_invalid.append(doc)

            doc_cnt += 1

        return False if self.documents_invalid else True

    def __repr__(self):
        return (
            f"{self.__module__}.{self.__class__.__name__} "
            f"[{len(self.documents)} valid documents]"
        )
