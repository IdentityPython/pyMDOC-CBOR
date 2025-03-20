from cwt import COSEKey
from typing import Union

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives import hashes, serialization

from pymdoccbor import settings

class MsoX509Fabric:
    """
    MsoX509Fabric helper class to create a new mso
    """

    def selfsigned_x509cert(self, encoding: str = "DER") -> Union[Certificate, bytes]:
        """
        Returns an X.509 certificate derived from the private key of the MSO Issuer

        :param encoding: str: the encoding to use, default is DER

        :return: Union[Certificate, bytes]: the X.509 certificate
        """
        ckey = COSEKey.from_bytes(self.private_key.encode())

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, settings.X509_COUNTRY_NAME),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, settings.X509_STATE_OR_PROVINCE_NAME),
            x509.NameAttribute(NameOID.LOCALITY_NAME, settings.X509_LOCALITY_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.X509_ORGANIZATION_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, settings.X509_COMMON_NAME),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ckey.key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            settings.X509_NOT_VALID_BEFORE
        ).not_valid_after(
            settings.X509_NOT_VALID_AFTER
        ).add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        settings.X509_SAN_URL
                    )
                ]
            ),
            critical=False,
            # Sign our certificate with our private key
        ).sign(ckey.key, hashes.SHA256())

        if not encoding:
            return cert
        else:
            return cert.public_bytes(
                getattr(serialization.Encoding, encoding)
            )
