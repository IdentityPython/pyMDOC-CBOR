# here some trials to have a publick raw key usable in phdr or uhdr
# but, again, it seems that only x509 works for COSE Sign1

```
ckey = COSEKey.from_bytes(self.private_key.encode())
pubkey = ckey.key.public_key()
self.public_key = CoseKey(
crv=COSEKEY_HAZMAT_CRV_MAP[pubkey.curve.name],
x=pubkey.public_numbers().x.to_bytes(32, 'big')
)

self.public_key = COSEKey(
crv=self.private_key.crv,
x=self.private_key.x,
y=self.private_key.y
)
```
