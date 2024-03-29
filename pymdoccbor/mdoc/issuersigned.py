import cbor2
from typing import Union

from pymdoccbor.mso.verifier import MsoVerifier
from pymdoccbor.mdoc.exceptions import MissingIssuerAuth


class IssuerSigned:
    """
    IssuerSigned helper class to handle issuer signed data

    nameSpaces provides the definition within which the data elements of
        the document are defined.
        A document may have multiple nameSpaces.

    IssuerAuth is a COSE_Sign1 ; The payload is the MobileSecurityObject,
        see ISO 18013-5 section 9.2.2.4

    issuerAuth is a list of [
        cbor({1: -7}) # Protected Header, find -7
            here https://datatracker.ietf.org/doc/html/rfc8152
        cbor({33: bytes}) # Unprotected Header containing X509 certificate
        cbor({24: bytes}) # Payload -> Mobile Security Object
        bytes # Signature
    ]
    """

    def __init__(self, nameSpaces: dict, issuerAuth: Union[dict, bytes]) -> None:
        """
        Create a new IssuerSigned instance

        :param nameSpaces: the namespaces
        :type nameSpaces: dict
        :param issuerAuth: the issuer auth
        :type issuerAuth: dict | bytes

        :raises MissingIssuerAuth: if no issuer auth is provided
        """
        self.namespaces: dict = nameSpaces

        if not issuerAuth:
            raise MissingIssuerAuth("issuerAuth must be provided")

        self.issuer_auth = MsoVerifier(issuerAuth)

    def dump(self) -> dict:
        """
        Returns a dict representation of the issuer signed data

        :return: the issuer signed data as dict
        :rtype: dict
        """
        return {
            'nameSpaces': self.namespaces,
            'issuerAuth': self.issuer_auth
        }

    def dumps(self) -> bytes:
        """
        Returns a CBOR representation of the issuer signed data

        :return: the issuer signed data as CBOR
        :rtype: bytes
        """
        return cbor2.dumps(
            {
                'nameSpaces': self.namespaces,
                'issuerAuth': self.issuer_auth.payload_as_cbor
            }
        )
