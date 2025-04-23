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
    MobileDocument class to handle the Mobile Document
    """

    _states = {
        True: "valid",
        False: "failed",
    }

    def __init__(self, docType: str, issuerSigned: dict, deviceSigned: dict = {}) -> None:
        """
        Initialize the MobileDocument object

        :param docType: str: the document type
        :param issuerSigned: dict: the issuerSigned info
        :param deviceSigned: dict: the deviceSigned info
        """

        if not docType:
            raise NoDocumentTypeProvided("You must provide a document type")

        self.doctype: str = docType  # eg: 'org.iso.18013.5.1.mDL'

        if not issuerSigned:
            raise NoSignedDocumentProvided("You must provide a signed document")

        self.issuersigned: List[IssuerSigned] = IssuerSigned(**issuerSigned)
        self.is_valid = False
        self.devicesigned: dict = deviceSigned

    def dump(self) -> dict:
        """
        It returns the document as a dict

        :return: dict: the document as a dict
        """
        return {
            'docType': self.doctype,
            'issuerSigned': self.issuersigned.dump()
        }
    
    def dumps(self) -> bytes:
        """
        It returns the AF binary repr as bytes

        :return: bytes: the document as bytes
        """
        return binascii.hexlify(self.dump())
    
    def dump(self) -> bytes:
        """
        It returns the document as bytes

        :return: dict: the document as bytes
        """
        return cbor2.dumps(
            cbor2.CBORTag(
                24, 
                value={
                    'docType': self.doctype,
                    'issuerSigned': self.issuersigned.dumps()
                }
            )
        )

    def verify(self) -> bool:
        """
        Verify the document signature

        :return: bool: True if the signature is valid, False otherwise
        """
        self.is_valid = self.issuersigned.issuer_auth.verify_signature()
        return self.is_valid

    def __repr__(self) -> str:
        return f"{self.__module__}.{self.__class__.__name__} [{self._states[self.is_valid]}]"


class MdocCbor:
    """
    MdocCbor class to handle the Mobile Document
    """

    def __init__(self) -> None:
        """
        Initialize the MdocCbor object
        """
        self.data_as_bytes: bytes = b""
        self.data_as_cbor_dict: dict = {}

        self.documents: List[MobileDocument] = []
        self.documents_invalid: list = []
        self.disclosure_map: dict = {}
    
    def loads(self, data: str) -> None:
        """
        Load the data from a AF Binary string

        :param data: str: the AF binary string
        """
        if isinstance(data, bytes):
            data = binascii.hexlify(data)

        self.data_as_bytes = binascii.unhexlify(data)
        self.data_as_cbor_dict = cbor2.loads(self.data_as_bytes)

    def dump(self) -> bytes:
        """
        Returns the CBOR representation of the mdoc as bytes
        """
        return self.data_as_bytes

    def dumps(self) -> bytes:
        """
        Returns the AF binary representation of the mdoc as bytes

        :return: bytes: the AF binary representation of the mdoc
        """
        return binascii.hexlify(self.data_as_bytes)

    @property
    def data_as_string(self) -> str:
        return self.dumps().decode()
    
    def _decode_claims(self, claims: list[dict]) -> dict:
        decoded_claims = {}

        for claim in claims:
            decoded = cbor2.loads(claim.value)

            if isinstance(decoded['elementValue'], cbor2.CBORTag):
                decoded_claims[decoded['elementIdentifier']] = decoded['elementValue'].value
            elif isinstance(decoded['elementValue'], list):
                claims_list = []

                for element in decoded['elementValue']:
                    claims_dict = {}
                    for key, value in element.items():
                        if isinstance(value, cbor2.CBORTag):
                            claims_dict[key] = value.value
                        else:
                            claims_dict[key] = value
                    claims_list.append(claims_dict)

                decoded_claims[decoded['elementIdentifier']] = claims_list
            else:
                decoded_claims[decoded['elementIdentifier']] = decoded['elementValue']

        return decoded_claims


    def verify(self) -> bool:
        """"
        Verify signatures of all documents contained in the mdoc

        :return: bool: True if all signatures are valid, False otherwise
        """

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

                for namespace, claims in mso.issuersigned.namespaces.items():
                    self.disclosure_map[namespace] = self._decode_claims(claims)

            except Exception as e:
                logger.error(
                    f"COSE Sign1 validation failed to the document number #{doc_cnt}. "
                    f"Then it is appended to self.documents_invalid: {e}"
                )
                self.documents_invalid.append(doc)

            doc_cnt += 1

        self.status = cdict.get('status', None)

        return False if self.documents_invalid else True

    def __repr__(self) -> str:
        return (
            f"{self.__module__}.{self.__class__.__name__} "
            f"[{len(self.documents)} valid documents]"
        )
