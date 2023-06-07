import datetime

from cwt import COSEKey

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization


class MsoX509Fabric:

    def selfsigned_x509cert(self, encoding: str = "DER"):

        # TODO: make this dynamic
        ckey = COSEKey.from_bytes(self.private_key.encode())

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
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
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for .. TODO:
            # see settings.PYMDOC_EXP_DELTA_HOURS
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        u"https://credential-issuer.oidc-federation.online"
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

    def trials(self):
        # here some desperated trials to have a publick raw key usable in phdr or uhdr
        # but, again, it seems that only x509 works for COSE Sign1

        #  ckey = COSEKey.from_bytes(self.private_key.encode())
        #  pubkey = ckey.key.public_key()
        #  self.public_key = CoseKey(
        #  crv=COSEKEY_HAZMAT_CRV_MAP[pubkey.curve.name],
        #  x=pubkey.public_numbers().x.to_bytes(32, 'big')
        #  )
        #
        #  self.public_key = COSEKey(
        #  crv=self.private_key.crv,
        #  x=self.private_key.x,
        #  y=self.private_key.y
        #  )
        pass
