import os
import base64

PKEY = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': b"<\xe5\xbc;\x08\xadF\x1d\xc5\x0czR'T&\xbb\x91\xac\x84\xdc\x9ce\xbf\x0b,\x00\xcb\xdd\xbf\xec\xa2\xa5",
    'KID': b"demo-kid"
}

def base64_urldecode(v: str) -> bytes:
    """Urlsafe base64 decoding. This function will handle missing
    padding symbols.

    :returns: the decoded data in bytes, format, convert to str use method '.decode("utf-8")' on result
    :rtype: bytes
    """
    padded = f"{v}{'=' * divmod(len(v), 4)[1]}"
    return base64.urlsafe_b64decode(padded)

decoded_x = base64_urldecode("dGLQBwQIPWjc2aA6zRc06wlNVxiw72PMwJlEXHEvP-E")
decoded_d = base64_urldecode("NOHGihpyjNa_xBSd17Wr4ynkSM-afunMgpoPoFkelhI")

PKEY_ED25519 = {
    'KTY': 'OKP',
    'CURVE': 'Ed25519',
    'ALG': 'EdDSA',
    'D': decoded_d,
    'X': decoded_x,
    'KID': b"demo-kid-ed25519"
}