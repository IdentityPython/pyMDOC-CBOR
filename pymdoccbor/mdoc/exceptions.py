# Aligns with https://github.com/eu-digital-identity-wallet/pyMDOC-CBOR
class MissingPrivateKey(Exception):
    pass


class NoDocumentTypeProvided(Exception):
    pass


class NoSignedDocumentProvided(Exception):
    pass


class MissingIssuerAuth(Exception):
    pass


class InvalidStatusDescriptor(Exception):
    pass
