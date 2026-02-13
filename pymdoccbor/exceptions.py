# Aligns with https://github.com/eu-digital-identity-wallet/pyMDOC-CBOR
class InvalidMdoc(Exception):
    """
    """


class UnsupportedMsoDataFormat(Exception):
    pass


class MsoPrivateKeyRequired(Exception):
    pass


class MsoX509ChainNotFound(Exception):
    pass
