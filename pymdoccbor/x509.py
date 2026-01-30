from typing import Any, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from pycose.keys import CoseKey


def selfsigned_x509cert(
    cert_info: dict[str, Any],
    private_key: CoseKey,
    encoding: str = "DER"
) -> Union[Certificate, bytes]:
    """
    Returns an X.509 certificate derived from the private key of the MSO Issuer

    :param cert_info: dict[str, Any]: the certificate information, should contain
        at least one of: country_name, state_or_province_name, locality_name,
        organization_name, common_name, not_valid_before, not_valid_after, san_url
    :param private_key: CoseKey: the private key to use for signing the certificate
    :param encoding: str: the encoding to use, default is DER
    :return: Union[Certificate, bytes]: the X.509 certificate
    """
    if not private_key:
        raise ValueError("private_key must be set")

    # convert the private key to a cryptography private key instance
    if hasattr(private_key, "kty") and private_key.kty is not None and hasattr(private_key.kty, "identifier"):
        if private_key.kty.identifier == 2:  # EC2Key
            private_key_inst = ec.derive_private_key(
                int.from_bytes(private_key['d'], byteorder="big"), ec.SECP256R1()
            )
        elif private_key.kty.identifier == 1:  # OKPKey
            private_key_inst = ed25519.Ed25519PrivateKey.from_private_bytes(
                private_key['d']
            )
        else:
            raise ValueError(f"Unsupported key type: {private_key.kty}")
    else:
        raise ValueError(
            "private_key.kty or private_key.kty.identifier is not set or unknown"
        )

    public_key_inst = private_key_inst.public_key()

    name_attributes = []
    if "country_name" in cert_info:
        name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, cert_info["country_name"]))
    if "state_or_province_name" in cert_info:
        name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, cert_info["state_or_province_name"]))
    if "locality_name" in cert_info:
        name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, cert_info["locality_name"]))
    if "organization_name" in cert_info:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, cert_info["organization_name"]))
    if "common_name" in cert_info:
        name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, cert_info["common_name"]))

    subject = issuer = x509.Name(name_attributes)

    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key_inst
    ).serial_number(
        x509.random_serial_number()
    )

    if "not_valid_before" in cert_info:
        cert_builder = cert_builder.not_valid_before(
            cert_info["not_valid_before"]
        )

    if "not_valid_after" in cert_info:
        cert_builder = cert_builder.not_valid_after(
            cert_info["not_valid_after"]
        )

    if "san_url" in cert_info:
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        cert_info["san_url"]
                    )
                ]
            ),
            critical=False,
            # Sign our certificate with our private key
        )

    cert = cert_builder.sign(private_key_inst, hashes.SHA256())

    if not encoding:
        return cert
    else:
        return cert.public_bytes(
            getattr(serialization.Encoding, encoding)
        )
