import cbor2
from asn1crypto.x509 import Certificate
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_der_x509_certificate
from pycose.messages import Sign1Message

from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MdocCbor
from pymdoccbor.mso.issuer import MsoIssuer
from pymdoccbor.tests.cert_data import CERT_DATA
from pymdoccbor.tests.pid_data import PID_DATA
from pymdoccbor.tests.pkey import PKEY, PKEY_ED25519, PKEY_RSA


def extract_mso(mdoc: dict):
    mso_data = mdoc["documents"][0]["issuerSigned"]["issuerAuth"][2]
    mso_cbortag = cbor2.loads(mso_data)
    mso = cbor2.loads(mso_cbortag.value)
    return mso


def test_mso_writer():
    validity = {"issuance_date": "2025-01-17", "expiry_date": "2025-11-13"}
    msoi = MsoIssuer(
        data=PID_DATA,
        private_key=PKEY,
        validity=validity,
        alg="ES256",
        cert_info=CERT_DATA
    )

    assert "eu.europa.ec.eudiw.pid.1" in msoi.hash_map
    assert msoi.hash_map["eu.europa.ec.eudiw.pid.1"]

    assert "eu.europa.ec.eudiw.pid.1" in msoi.disclosure_map
    assert msoi.disclosure_map["eu.europa.ec.eudiw.pid.1"]
    assert msoi.disclosure_map["eu.europa.ec.eudiw.pid.1"].values().__len__() == PID_DATA["eu.europa.ec.eudiw.pid.1"].values().__len__()

    mso = msoi.sign()

    Sign1Message.decode(mso.encode())


def test_mdoc_issuer():
    validity = {"issuance_date": "2025-01-17", "expiry_date": "2025-11-13"}
    mdoci = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
        cert_info=CERT_DATA
    )
    with open("pymdoccbor/tests/certs/fake-cert.pem", "rb") as file:
        fake_cert_file = file.read()
        asl_signing_cert = x509.load_pem_x509_certificate(fake_cert_file)
        _asl_signing_cert = asl_signing_cert.public_bytes(getattr(serialization.Encoding, "DER"))
        status_list = {
            "status_list": {
                "idx": 0,
                "uri": "https://issuer.com/statuslists",
                "certificate": _asl_signing_cert,
            }
        }
        mdoc = mdoci.new(
            doctype="eu.europa.ec.eudiw.pid.1",
            data=PID_DATA,
            devicekeyinfo=PKEY,
            validity=validity,
            revocation=status_list
        )

    mdocp = MdocCbor()
    aa = cbor2.dumps(mdoc)
    mdocp.loads(aa)
    assert mdocp.verify() is True

    mdoci.dump()
    mdoci.dumps()

    # check mso content for status list
    mso = extract_mso(mdoc)
    status_list = mso["status"]["status_list"]
    assert status_list["idx"] == 0
    assert status_list["uri"] == "https://issuer.com/statuslists"
    cert_bytes = status_list["certificate"]
    cert: Certificate = load_der_x509_certificate(cert_bytes)
    assert "Test ASL Issuer" in cert.subject.rfc4514_string()


def test_mdoc_issuer_EdDSA():
    validity = {"issuance_date": "2025-01-17", "expiry_date": "2025-11-13"}
    mdoci = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
        cert_info=CERT_DATA
    )
    with open("pymdoccbor/tests/certs/fake-cert.pem", "rb") as file:
        fake_cert_file = file.read()
        asl_signing_cert = x509.load_pem_x509_certificate(fake_cert_file)
        _asl_signing_cert = asl_signing_cert.public_bytes(getattr(serialization.Encoding, "DER"))
        status_list = {
            "status_list": {
                "idx": 0,
                "uri": "https://issuer.com/statuslists",
                "certificate": _asl_signing_cert,
            }
        }
        mdoc = mdoci.new(
            doctype="eu.europa.ec.eudiw.pid.1",
            data=PID_DATA,
            devicekeyinfo=PKEY_ED25519,
            validity=validity,
            revocation=status_list
        )

    mdocp = MdocCbor()
    aa = cbor2.dumps(mdoc)
    mdocp.loads(aa)
    assert mdocp.verify() is True

    mdoci.dump()
    mdoci.dumps()

    # check mso content for status list
    mso = extract_mso(mdoc)
    status_list = mso["status"]["status_list"]
    assert status_list["idx"] == 0
    assert status_list["uri"] == "https://issuer.com/statuslists"
    cert_bytes = status_list["certificate"]
    cert: Certificate = load_der_x509_certificate(cert_bytes)
    assert "Test ASL Issuer" in cert.subject.rfc4514_string()


def test_mdoc_issuer_RSA():
    validity = {"issuance_date": "2025-01-17", "expiry_date": "2025-11-13"}
    mdoci = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
        cert_info=CERT_DATA
    )
    with open("pymdoccbor/tests/certs/fake-cert.pem", "rb") as file:
        fake_cert_file = file.read()
        asl_signing_cert = x509.load_pem_x509_certificate(fake_cert_file)
        _asl_signing_cert = asl_signing_cert.public_bytes(getattr(serialization.Encoding, "DER"))
        status_list = {
            "status_list": {
                "idx": 0,
                "uri": "https://issuer.com/statuslists",
                "certificate": _asl_signing_cert,
            }
        }
        mdoc = mdoci.new(
            doctype="eu.europa.ec.eudiw.pid.1",
            data=PID_DATA,
            devicekeyinfo=PKEY_RSA,
            validity=validity,
            revocation=status_list
        )

    mdocp = MdocCbor()
    aa = cbor2.dumps(mdoc)
    mdocp.loads(aa)
    assert mdocp.verify() is True

    mdoci.dump()
    mdoci.dumps()

    # check mso content for status list
    mso = extract_mso(mdoc)
    status_list = mso["status"]["status_list"]
    assert status_list["idx"] == 0
    assert status_list["uri"] == "https://issuer.com/statuslists"
    cert_bytes = status_list["certificate"]
    cert: Certificate = load_der_x509_certificate(cert_bytes)
    assert "Test ASL Issuer" in cert.subject.rfc4514_string()
