import logging
from typing import Union

import cbor2
import cryptography
from cryptography.exceptions import InvalidSignature
from pycose.keys import EC2Key
from pycose.messages import Sign1Message

from pymdoccbor import settings
from pymdoccbor.exceptions import (MsoX509ChainNotFound,
                                   UnsupportedMsoDataFormat)
from pymdoccbor.tools import bytes2CoseSign1, cborlist2CoseSign1

logger = logging.getLogger("pymdoccbor")


class MsoVerifier:
    """
    Parameters
        data: CBOR TAG 24

    Example:
        MsoParser(mdoc['documents'][0]['issuerSigned']['issuerAuth'])

    Note
        The signature is contained in an untagged COSE_Sign1
        structure as defined in RFC 8152.
    """

    def __init__(self, data: Union[cbor2.CBORTag, bytes, list]) -> None:
        """
        Initialize the MsoParser object

        :param data: Union[cbor2.CBORTag, bytes, list]: the data to parse
        """

        self._data = data

        # not used
        if isinstance(self._data, bytes):
            self.object: Sign1Message = bytes2CoseSign1(
                cbor2.dumps(cbor2.CBORTag(18, value=self._data)))
        elif isinstance(self._data, list):
            self.object: Sign1Message = cborlist2CoseSign1(self._data)
        else:
            raise UnsupportedMsoDataFormat(
                f"MsoParser only supports raw bytes and list, a {type(data)} was provided"
            )

        self.object.key = None
        self.public_key: cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey = None
        self.x509_certificates: list = []
        self.verified_root = None  # Will store the trusted root that verified the chain

    @property
    def payload_as_cbor(self) -> dict:
        """
        It returns the payload as a CBOR TAG

        :return: dict: the payload as a CBOR TAG 24
        """
        return cbor2.loads(self.object.payload)

    @property
    def payload_as_raw(self):
        return self.object.payload

    @property
    def payload_as_dict(self):
        return cbor2.loads(
            cbor2.loads(self.object.payload).value
        )

    @property
    def raw_public_keys(self) -> list[Union[bytes, dict]]:
        """
            Extracts public keys from x509 certificates found in the MSO.
            This method searches for x509 certificates in both the protected header (phdr)
            and unprotected header (uhdr) of the COSE_Sign1 object. It handles certificate
            data in various formats, including:
            - `bytes`: Returns a list containing the raw bytes of the certificate.
            - `list`: Returns the list of certificates as-is.
            - `dict`: Wraps the dictionary in a list and returns it.
            If no valid x509 certificates are found, an `MsoX509ChainNotFound` exception
            is raised. Unexpected types are logged as warnings.
            :return: list[Any]: A list of certificates in their respective formats.
            :raises MsoX509ChainNotFound: If no x509 certificates are found.
        """
        merged = self.object.phdr.copy()
        merged.update(self.object.uhdr)
        _mixed_heads = merged.items()
        for h, v in _mixed_heads:
            if h.identifier == 33:
                if isinstance(v, bytes):
                    return [v]
                elif isinstance(v, list):
                    return v
                elif isinstance(v, dict):
                    return [v]
                else:
                    logger.warning(
                        f"Unexpected type for public key: {type(v)}. "
                        "Expected bytes, list or dict."
                    )
                    continue

        raise MsoX509ChainNotFound(
            "I can't find any valid X509certs, identified by label number 33, "
            "in this MSO."
        )

    def attest_public_key(self, trusted_root_certs: list = None):
        """
        Verify the X.509 certificate chain.

        Args:
            trusted_root_certs: List of trusted root certificates (x509.Certificate objects)
                               If None, skips chain validation (backward compatible)

        Returns:
            The trusted root certificate that signed the DS cert, or None if validation skipped
        """
        if trusted_root_certs is None:
            logger.warning(
                "Certificate chain validation skipped. "
                "Pass trusted_root_certs parameter to verify() to enable X.509 chain validation."
            )
            return None

        # Load DS certificate (first in chain)
        ds_cert = self.x509_certificates[0] if self.x509_certificates else None
        if not ds_cert:
            raise ValueError("No DS certificate found in MSO")

        # Verify DS cert is signed by one of the trusted roots
        verified_root = None
        for root_cert in trusted_root_certs:
            try:
                # Verify signature
                root_cert.public_key().verify(
                    ds_cert.signature,
                    ds_cert.tbs_certificate_bytes,
                    ds_cert.signature_algorithm_parameters
                )
                verified_root = root_cert
                logger.info(f"Certificate chain verified with root: {root_cert.subject}")
                break
            except InvalidSignature:
                continue
            except Exception as exc:
                logger.warning(f"Error verifying with root cert: {exc}")
                continue

        if not verified_root:
            raise ValueError("DS certificate not signed by any trusted root")

        # Verify certificate validity dates
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)

        if ds_cert.not_valid_before_utc > now:
            raise ValueError(f"DS certificate not yet valid (valid from {ds_cert.not_valid_before_utc})")

        if ds_cert.not_valid_after_utc < now:
            raise ValueError(
                f"DS certificate expired (valid until {ds_cert.not_valid_after_utc})"
            )

        logger.info("Certificate chain and validity verified successfully")
        return verified_root

    def load_public_key(self, trusted_root_certs: list = None) -> None:
        """
        Load the public key from the x509 certificate

        Args:
            trusted_root_certs: List of trusted root certificates for chain validation
        :return: None
        """
        for i in self.raw_public_keys:
            self.x509_certificates.append(
                cryptography.x509.load_der_x509_certificate(i)
            )

        self.verified_root = self.attest_public_key(trusted_root_certs)

        self.public_key = self.x509_certificates[0].public_key()

        key = EC2Key(
            crv=settings.COSEKEY_HAZMAT_CRV_MAP[self.public_key.curve.name],
            x=self.public_key.public_numbers().x.to_bytes(
                settings.CRV_LEN_MAP[self.public_key.curve.name], 'big'
            ),
            y=self.public_key.public_numbers().y.to_bytes(
                settings.CRV_LEN_MAP[self.public_key.curve.name], 'big'
            )
        )
        self.object.key = key

    def verify_signature(self, trusted_root_certs: list = None) -> bool:
        """"
        Verify the signature of the MSO

        Args:
            trusted_root_certs: List of trusted root certificates for chain validation
        :return: bool: True if the signature is valid, False otherwise
        """
        if not self.object.key:
            self.load_public_key(trusted_root_certs)

        return self.object.verify_signature()

    def verify_element_hashes(self, namespaces: dict) -> dict:
        """
        Verify that disclosed elements match their hashes in the MSO.

        Args:
            namespaces: The nameSpaces dict from IssuerSigned containing IssuerSignedItems

        Returns:
            dict: Results with 'valid' (bool), 'total' (int), 'verified' (int), 'failed' (list)
        """
        import hashlib

        mso_data = self.payload_as_dict
        value_digests = mso_data.get('valueDigests', {})

        results = {
            'valid': True,
            'total': 0,
            'verified': 0,
            'failed': []
        }

        for namespace, items in namespaces.items():
            if namespace not in value_digests:
                logger.warning(f"Namespace {namespace} not found in MSO valueDigests")
                continue

            namespace_digests = value_digests[namespace]

            for item_bytes in items:
                results['total'] += 1

                # item_bytes might be a CBORTag object, need to encode it
                if isinstance(item_bytes, cbor2.CBORTag):
                    item_bytes_raw = cbor2.dumps(item_bytes)
                else:
                    item_bytes_raw = item_bytes

                # Decode to get digestID
                try:
                    item_data = cbor2.loads(item_bytes_raw)
                    if isinstance(item_data, cbor2.CBORTag) and item_data.tag == 24:
                        item_content = cbor2.loads(item_data.value)
                    else:
                        item_content = item_data

                    digest_id = item_content.get('digestID')
                    element_id = item_content.get('elementIdentifier')

                    # Compute hash of the full tagged bytes
                    computed_hash = hashlib.sha256(item_bytes_raw).digest()

                    # Get expected hash from MSO
                    expected_hash = namespace_digests.get(digest_id)

                    if expected_hash is None:
                        logger.error(f"digestID {digest_id} not found in MSO for {namespace}/{element_id}")
                        results['failed'].append({
                            'namespace': namespace,
                            'digestID': digest_id,
                            'elementIdentifier': element_id,
                            'reason': 'digestID not in MSO'
                        })
                        results['valid'] = False
                        continue

                    if computed_hash != expected_hash:
                        logger.error(f"Hash mismatch for {namespace}/{element_id} (digestID={digest_id})")
                        results['failed'].append({
                            'namespace': namespace,
                            'digestID': digest_id,
                            'elementIdentifier': element_id,
                            'reason': 'hash mismatch',
                            'expected': expected_hash.hex(),
                            'computed': computed_hash.hex()
                        })
                        results['valid'] = False
                    else:
                        results['verified'] += 1
                        logger.debug(f"Hash verified for {namespace}/{element_id}")

                except Exception as e:
                    logger.error(f"Error verifying element hash: {e}")
                    results['failed'].append({
                        'namespace': namespace,
                        'reason': f'exception: {e}'
                    })
                    results['valid'] = False

        return results
