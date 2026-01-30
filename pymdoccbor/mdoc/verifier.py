import binascii
import logging
from typing import List

import cbor2

from pymdoccbor.exceptions import InvalidMdoc
from pymdoccbor.mdoc.exceptions import (NoDocumentTypeProvided,
                                        NoSignedDocumentProvided)
from pymdoccbor.mdoc.issuersigned import IssuerSigned

logger = logging.getLogger('pymdoccbor')


class MobileDocument:
    """
    MobileDocument class to handle the Mobile Document
    """

    _states = {
        True: "valid",
        False: "failed",
    }

    def __init__(self, docType: str, issuerSigned: dict, deviceSigned: dict = {}, errors: dict = None) -> None:
        """
        Initialize the MobileDocument object

        :param docType: str: the document type
        :param issuerSigned: dict: the issuerSigned info
        :param deviceSigned: dict: the deviceSigned info
        :param errors: dict: optional errors field (ISO 18013-5 status != 0)
        """

        if not docType:
            raise NoDocumentTypeProvided("You must provide a document type")

        self.doctype: str = docType  # eg: 'org.iso.18013.5.1.mDL'

        if not issuerSigned:
            raise NoSignedDocumentProvided("You must provide a signed document")

        self.issuersigned: List[IssuerSigned] = IssuerSigned(**issuerSigned)
        self.is_valid = False
        self.hash_verification = None  # Will store hash verification results
        self.devicesigned: dict = deviceSigned
        self.errors: dict = errors if errors is not None else {}

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
        doc_dict = {
            'docType': self.doctype,
            'issuerSigned': self.issuersigned.dumps()
        }

        # Include errors field if present (ISO 18013-5 status != 0)
        if self.errors:
            doc_dict['errors'] = self.errors

        return cbor2.dumps(
            cbor2.CBORTag(
                24,
                value=doc_dict
            )
        )

    def verify(self, trusted_root_certs: list = None, verify_hashes: bool = True) -> bool:
        """
        Verify the document signature and optionally element hashes

        Args:
            trusted_root_certs: List of trusted root certificates for chain validation
            verify_hashes: If True, also verify element hashes against MSO
        :return: bool: True if the signature is valid, False otherwise
        """
        # Verify signature
        self.is_valid = self.issuersigned.issuer_auth.verify_signature(trusted_root_certs)

        # Verify element hashes if requested
        if verify_hashes and self.is_valid:
            hash_results = self.issuersigned.issuer_auth.verify_element_hashes(
                self.issuersigned.namespaces
            )
            self.hash_verification = hash_results
            self.is_valid = self.is_valid and hash_results['valid']

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
                    # Handle simple values in lists (strings, numbers, etc.)
                    if not isinstance(element, dict):
                        claims_list.append(element)
                        continue

                    # Handle dict elements
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

    def verify(self, trusted_root_certs: list = None, verify_hashes: bool = True) -> bool:
        """
        Verify signatures of all documents contained in the mdoc

        Args:
            trusted_root_certs: List of trusted root certificates (x509.Certificate objects)
                               for chain validation. If None, skips chain validation.
            verify_hashes: If True, also verify element hashes against MSO valueDigests
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
                if mso.verify(trusted_root_certs, verify_hashes):
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
