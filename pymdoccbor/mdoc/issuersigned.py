from typing import Union

import cbor2

from pymdoccbor.mso.verifier import MsoVerifier


class IssuerSigned:
    """
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

    def __init__(self, nameSpaces: dict, issuerAuth: Union[cbor2.CBORTag, dict, bytes]) -> None:
        """
        Initialize the IssuerSigned object

        :param nameSpaces: dict: the nameSpaces of the document
        :param issuerAuth: Union[dict, bytes]: the issuerAuth info of the document
        """

        self.namespaces: dict = nameSpaces

        if not issuerAuth:
            raise ValueError("issuerAuth must be provided")

        #  if isinstance(ia, dict):
        self.issuer_auth = MsoVerifier(issuerAuth)

    def dump(self) -> dict:
        """
        It returns the issuerSigned as a dict

        :return: dict: the issuerSigned as a dict
        """

        return {
            'nameSpaces': self.namespaces,
            'issuerAuth': self.issuer_auth
        }

    def dumps(self) -> bytes:
        """
        It returns the issuerSigned as bytes

        :return: dict: the issuerSigned as bytes
        """

        return cbor2.dumps(
            {
                'nameSpaces': self.namespaces,
                'issuerAuth': self.issuer_auth.payload_as_cbor
            }
        )
