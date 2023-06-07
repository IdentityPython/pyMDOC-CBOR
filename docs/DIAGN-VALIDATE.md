# NOTES

#### Document structure

````
{
 'version': '1.0',
 'documents': Array of $doc,
 'status': 0
}
````

Where a single `$doc` it something like as follow.

````
{
'docType': 'org.iso.18013.5.1.mDL'
'issuerSigned': {
    'nameSpaces'
        'org.iso.18013.5.1' -> Arrays of digests
            [
                Tag(
                    24, 
                    b'\xa4hdigestID\x00frandomX \x87\x98d[ \xea \x0e\x19\xff\xab\xac\x92bK\xeej\xecc\xac\xee\xde\xcf\xb1\xb8\x00w\xd2+\xfc \xe9qelementIdentifierkfamily_namelelementValuecDoe'
                ), -> {'digestID': 0, 'random': b'\x87\x98d[ \xea \x0e\x19\xff\xab\xac\x92bK\xeej\xecc\xac\xee\xde\xcf\xb1\xb8\x00w\xd2+\xfc \xe9', 'elementIdentifier': 'family_name', 'elementValue': 'Doe'}
                ...
            ]
    'issuerAuth': ->  TAG 18 Contains the mobile security object (MSO) for issuer data authentication, an Array of the elements below
        cbor({1: -7}) # Protected Header, find -7 here https://datatracker.ietf.org/doc/html/rfc8152 -> ES256 SHA-256
        {33: cbor tag( -17)} # Unprotected header -> the x5chain element has the temporary identifer 33 registered in the IANA registry.
        Tag(24, cbor(payload) -> It's a MobileSecurityObjectBytes
            {
             'version': '1.0',
             'digestAlgorithm': 'SHA-256',
             'valueDigests': {
                'org.iso.18013.5.1': {
                    0: b'u\x16s3\xb4{l+\xfb\x86\xec\xcc\x1fC\x8c\xf5z\xf0U7\x1a\xc5^\x1e5\x9e \xf2T\xad\xce\xbf',
                    1: b'g\xe59\xd6\x13\x9e\xbd\x13\x1a\xefD\x1bDVE\xdd\x83\x1b+7[9\x0c\xa5\xefby\xb2\x05\xedEq',
                    2: b"3\x947-\xdbx\x05?6\xd5\xd8ix\x0ea\xed\xa3\x13\xd4J9 \x92\xad\x8e\x05'\xa2\xfb\xfeU\xae",
                    3: b'.5\xad<NQK\xb6{\x1a\x9d\xb5\x1c\xe7NL\xb9\xb7\x14nA\xacR\xda\xc9\xce\x86\xb8a=\xb5U',
                    4: b'\xea\\3\x04\xbb|J\x8d\xcbQ\xc4\xc1;e&O\x84UA4\x13B\t<\xcaxn\x05\x8f\xac-Y',
                    5: b'\xfa\xe4\x87\xf6\x8bz\x0e\x87\xa7IwNV\xe9\xe1\xdc:\x8e\xc7\xb7~I\r!\xf0\xe1\xd3GVa\xaa\x1d',
                    6: b'}\x83\xe5\x07\xaew\xdb\x81]\xe4\xd8\x03\xb8\x85U\xd0Q\x1d\x89L\x89t9\xf5w@VAj\x1cu3',
                    7: b'\xf0T\x9a\x14_\x1c\xf7\\\xbe\xef\xfa\x88\x1dHW\xddC\x8db|\xf3!t\xb1s\x1cL8\xe1,\xa96',
                    8: b'\xb6\x8c\x8a\xfc\xb2\xaa\xf7\xc5\x81A\x1d(w\xde\xf1U\xbe.\xb1!\xa4+\xc9\xba[s\x127~\x06\x8ff',
                    9: b'\x0b5\x87\xd1\xdd\x0c*\x07\xa3[\xfb\x12\r\x99\xa0\xab\xfb]\xf5he\xbb\x7f\xa1\\\xc8\xb5jf\xdfn\x0c',
                    10: b'\xc9\x8a\x17\x0c\xf3n\x11\xab\xb7$\xe9\x8au\xa54=\xfa+n\xd3\xdf.\xcf\xbb\x8e\xf2\xeeU\xddA\xc8\x81',
                    11: b'\xb5}\xd06x/{\x14\xc6\xa3\x0f\xaa\xaa\xe6\xcc\xd5\x05L\xe8\x8b\xdf\xa5\x1a\x01k\xa7^\xda\x1e\xde\xa9H',
                    12: b'e\x1f\x876\xb1\x84\x80\xfe%*\x03"N\xa0\x87\xb5\xd1\x0c\xa5HQF\xc6|t\xacN\xc3\x11-L:'},
                'org.iso.18013.5.1.US': {
                    0: b'\xd8\x0b\x83\xd2Qs\xc4\x84\xc5d\x06\x10\xff\x1a1\xc9I\xc1\xd94\xbfL\xf7\xf1\x8dR#\xb1]\xd4\xf2\x1c',
                    1: b"M\x80\xe1\xe2\xe4\xfb$m\x97\x89T'\xcep\x00\xbbY\xbb$\xc8\xcd\x00>\xcf\x94\xbf5\xbb\xd2\x91~4",
                    2: b'\x8b3\x1f;h[\xca7.\x855\x1a%\xc9HJ\xb7\xaf\xcd\xf0\xd2#1\x05Q\x1fw\x8d\x98\xc2\xf5D',
                    3: b'\xc3C\xaf\x1b\xd1i\x07\x15C\x91a\xab\xa77\x02\xc4t\xab\xf9\x92\xb2\x0c\x9f\xb5\\6\xa36\xeb\xe0\x1a\x87'
                }
               },
             'deviceKeyInfo': {
                'deviceKey': {
                    1: 2,
                    -1: 1,
                    -2: b'\x961=lc\xe2N3rt+\xfd\xb1\xa3;\xa2\xc8\x97\xdc\xd6\x8a\xb8\xc7S\xe4\xfb\xd4\x8d\xcak\x7f\x9a',
                    -3: b'\x1f\xb3&\x9e\xddA\x88W\xde\x1b9\xa4\xe4\xa4K\x92\xfaHL\xaar,"\x82\x88\xf0\x1d\x0c\x03\xa2\xc3\xd6'}
                },
                'docType': 'org.iso.18013.5.1.mDL',
                'validityInfo': {
                    'signed': Tag(0, '2020-10-01T13:30:02Z'),
                    'validFrom': Tag(0, '2020-10-01T13:30:02Z'),
                    'validUntil': Tag(0, '2021-10-01T13:30:02Z')
                }
            }
        ),
        Signature?
    }
'deviceSigned'
    {'nameSpaces': Tag(24, b'\xa0'),
     'deviceAuth': {
        'deviceMac': [
            b'\xa1\x01\x05',
            {},
            None,
            b' \rs\xde\xd7\x87\xc6FR\xdc\x8e\xe7C\xea\x83\xa5&\rZ2\x83\xfd\xdc\x91\x9b{\x9c\xfbHj\xdd\xb2'
        ]
    }
}
````

Here a diagnostic representation

````
import binascii
import cbor_diag

BIN_ISSUED_MDOC = binascii.unhexlify(ISSUED_MDOC)
print(cbor_diag.cbor2diag(BIN_ISSUED_MDOC))

{
    "version": "1.0",
    "documents": [
        {
            "docType": "org.iso.18013.5.1.mDL",
            "issuerSigned": {
                "nameSpaces": {
                    "org.iso.18013.5.1": [
                        24_0(<<{
                            "digestID": 0,
                            "random": h'8798645b20ea200e19ffabac92624bee6aec63aceedecfb1b80077d22bfc20e9',
                            "elementIdentifier": "family_name",
                            "elementValue": "Doe",
                        }>>),
                        24_0(<<{
                            "digestID": 3,
                            "random": h'b23f627e8999c706df0c0a4ed98ad74af988af619b4bb078b89058553f44615d',
                            "elementIdentifier": "issue_date",
                            "elementValue": 1004_1("2019-10-20"),
                        }>>),
                        24_0(<<{
                            "digestID": 4,
                            "random": h'c7ffa307e5de921e67ba5878094787e8807ac8e7b5b3932d2ce80f00f3e9abaf',
                            "elementIdentifier": "expiry_date",
                            "elementValue": 1004_1("2024-10-20"),
                        }>>),
                        24_0(<<{
                            "digestID": 7,
                            "random": h'26052a42e5880557a806c1459af3fb7eb505d3781566329d0b604b845b5f9e68',
                            "elementIdentifier": "document_number",
                            "elementValue": "123456789",
                        }>>),
                        24_0(<<{
                            "digestID": 8,
                            "random": h'd094dad764a2eb9deb5210e9d899643efbd1d069cc311d3295516ca0b024412d',
                            "elementIdentifier": "portrait",
                            "elementValue": h'ffd8ffe000104a46494600010101009000900000ffdb004300130d0e110e0c13110f11151413171d301f1d1a1a1d3a2a2c2330453d4947443d43414c566d5d4c51685241435f82606871757b7c7b4a5c869085778f6d787b76ffdb0043011415151d191d381f1f38764f434f7676767676767676767676767676767676767676767676767676767676767676767676767676767676767676767676767676ffc00011080018006403012200021101031101ffc4001b00000301000301000000000000000000000005060401020307ffc400321000010303030205020309000000000000010203040005110612211331141551617122410781a1163542527391b2c1f1ffc4001501010100000000000000000000000000000001ffc4001a110101010003010000000000000000000000014111213161ffda000c03010002110311003f00a5bbde22da2329c7d692bc7d0d03f52cfb0ff75e7a7ef3e7709723a1d0dae146ddfbb3c039ce07ad2bd47a7e32dbb8dd1d52d6ef4b284f64a480067dfb51f87ffb95ff00eb9ff14d215de66af089ce44b7dbde9cb6890a2838eddf18078f7add62d411ef4db9b10a65d6b95a147381ea0d495b933275fe6bba75c114104a8ba410413e983dff004f5af5d34b4b4cde632d0bf1fd1592bdd91c6411f3934c2fa6af6b54975d106dcf4a65ae56e856001ebc03c7ce29dd9eef1ef10fc447dc9da76ad2aee93537a1ba7e4f70dd8eff0057c6dffb5e1a19854a83758e54528750946ec6704850cd037bceb08b6d7d2cc76d3317fc7b5cc04fb6707269c5c6e0c5b60ae549242123b0e493f602a075559e359970d98db89525456b51c951c8afa13ea8e98e3c596836783d5c63f5a61a99fdb7290875db4be88ab384bbbbbfc7183fdeaa633e8951db7da396dc48524fb1a8bd611a5aa2a2432f30ab420a7a6d3240c718cf031fa9ef4c9ad550205aa02951df4a1d6c8421b015b769db8c9229837ea2be8b1b0d39d0eba9c51484efdb8c0efd8d258daf3c449699f2edbd4584e7af9c64e3f96b9beb28d4ac40931e6478c8e76a24a825449501d867d2b1dcdebae99b9c752ae4ecd6dde4a179c1c1e460938f9149ef655e515c03919a289cb3dca278fb7bf177f4faa829dd8ce3f2ac9a7ecde490971fafd7dce15eed9b71c018c64fa514514b24e8e4f8c5c9b75c1e82579dc1233dfec08238f6add62d391acc1c5256a79e706d52d431c7a0145140b9fd149eb3a60dc5e88cbbc2da092411e9dc71f39a7766b447b344e847dcac9dcb5abba8d145061d43a6fcf1e65cf15d0e90231d3dd9cfe62995c6dcc5ca12a2c904a15f71dd27d451453e09d1a21450961cbb3ea8a956433b781f1ce33dfed54f0e2b50a2b71d84ed6db18028a28175f74fc6bda105c529a791c25c4f3c7a11f71586268f4a66b726e33de9ea6f1b52b181c760724e47b514520a5a28a283ffd9',
                        }>>),
                        24_0(<<{
                            "digestID": 9,
                            "random": h'4599f81beaa2b20bd0ffcc9aa03a6f985befab3f6beaffa41e6354cdb2ab2ce4',
                            "elementIdentifier": "driving_privileges",
                            "elementValue": [
                                {
                                    "vehicle_category_code": "A",
                                    "issue_date": 1004_1("2018-08-09"),
                                    "expiry_date": 1004_1("2024-10-20"),
                                },
                                {
                                    "vehicle_category_code": "B",
                                    "issue_date": 1004_1("2017-02-23"),
                                    "expiry_date": 1004_1("2024-10-20"),
                                },
                            ],
                        }>>),
                    ],
                },
                "issuerAuth": [
                    h'a10126',
                    {
                        33_0: h'308201ce30820174a003020102021401ec51916031e6898e8fc7864af5e6d5f86602b6300a06082a8648ce3d04030230233114301206035504030c0b75746f7069612069616361310b3009060355040613025553301e170d3230313030313030303030305a170d3231313030313030303030305a30213112301006035504030c0975746f706961206473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d03010703420004ace7ab7340e5d9648c5a72a9a6f56745c7aad436a03a43efea77b5fa7b88f0197d57d8983e1b37d3a539f4d588365e38cbbf5b94d68c547b5bc8731dcd2f146ba38187308184301e0603551d120417301581136578616d706c65406578616d706c652e636f6d301c0603551d1f041530133011a00fa00d820b6578616d706c652e636f6d301d0603551d0e0416041414e29017a6c35621ffc7a686b7b72db06cd12351300e0603551d0f0101ff04040302078030150603551d250101ff040b3009060728818c5d050102300a06082a8648ce3d0403020348003045022100bac6f93a8bacf0fc9aeac1c89a5c9293af2076942e9e972882a113640330702702207b7b73c0444371a4c94c9c888ddfe553ffde84ca492fd64dfbf02ad46a31cbc8',
                    },
                    h'd81859039da66776657273696f6e63312e306f646967657374416c676f726974686d675348412d3235366c76616c756544696765737473a2716f72672e69736f2e31383031332e352e31ad00582075167333b47b6c2bfb86eccc1f438cf57af055371ac55e1e359e20f254adcebf01582067e539d6139ebd131aef441b445645dd831b2b375b390ca5ef6279b205ed45710258203394372ddb78053f36d5d869780e61eda313d44a392092ad8e0527a2fbfe55ae0358202e35ad3c4e514bb67b1a9db51ce74e4cb9b7146e41ac52dac9ce86b8613db555045820ea5c3304bb7c4a8dcb51c4c13b65264f845541341342093cca786e058fac2d59055820fae487f68b7a0e87a749774e56e9e1dc3a8ec7b77e490d21f0e1d3475661aa1d0658207d83e507ae77db815de4d803b88555d0511d894c897439f5774056416a1c7533075820f0549a145f1cf75cbeeffa881d4857dd438d627cf32174b1731c4c38e12ca936085820b68c8afcb2aaf7c581411d2877def155be2eb121a42bc9ba5b7312377e068f660958200b3587d1dd0c2a07a35bfb120d99a0abfb5df56865bb7fa15cc8b56a66df6e0c0a5820c98a170cf36e11abb724e98a75a5343dfa2b6ed3df2ecfbb8ef2ee55dd41c8810b5820b57dd036782f7b14c6a30faaaae6ccd5054ce88bdfa51a016ba75eda1edea9480c5820651f8736b18480fe252a03224ea087b5d10ca5485146c67c74ac4ec3112d4c3a746f72672e69736f2e31383031332e352e312e5553a4005820d80b83d25173c484c5640610ff1a31c949c1d934bf4cf7f18d5223b15dd4f21c0158204d80e1e2e4fb246d97895427ce7000bb59bb24c8cd003ecf94bf35bbd2917e340258208b331f3b685bca372e85351a25c9484ab7afcdf0d2233105511f778d98c2f544035820c343af1bd1690715439161aba73702c474abf992b20c9fb55c36a336ebe01a876d6465766963654b6579496e666fa1696465766963654b6579a40102200121582096313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c753e4fbd48dca6b7f9a2258201fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03a2c3d667646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fa3667369676e6564c074323032302d31302d30315431333a33303a30325a6976616c696446726f6dc074323032302d31302d30315431333a33303a30325a6a76616c6964556e74696cc074323032312d31302d30315431333a33303a30325a',
                    h'cff12c17d4739aba806035a9cb2b34ae8a830cef4f329289f9a3ebd302dd6b99c584068257569397b92ba9aa5128554eb05d1273dafea313da4aff6b01a5fb3f',
                ],
            },
            "deviceSigned": {
                "nameSpaces": 24_0(<<{}>>),
                "deviceAuth": {
                    "deviceMac": [
                        h'a10105',
                        {},
                        null,
                        h'200d73ded787c64652dc8ee743ea83a5260d5a3283fddc919b7b9cfb486addb2',
                    ],
                },
            },
        },
    ],
    "status": 0,
}

````

#### `issuerAuth` with TAG 33

The `x5chain` element has the temporary identifer 33 registered in the IANA registry.

Please note: ISO 18013-5 uses draft not standards yet, like:

 - draft-ietf-cbor-date-tag-01 -> became an RFC here: https://www.rfc-editor.org/rfc/rfc8943.html
 - draft-ietf-cose-x509-08	


#### 9.3 Validation and inspection procedures

 1. Validate the certificate included in the MSO header according to Clause 9.3.3.
 2. Verify  the  digital  signature  of  the  IssuerAuth  structure  (see  Clause 9.1.2.4)  using  the 
working_public_key,  working_public_key_parameters,  and  working_public_key_algorithm  from 
the certificate validation procedure of step 1.
 3. Calculate  the digest value  for every IssuerSignedItem returned in  the DeviceResponse
structure according  to  Clause 9.1.2.5  and  verify  that  these  calculated  digests  equal  the 
corresponding digest values in the MSO.
 4. Verify that the DocType in the MSO matches the relevant DocType in the Documents structure.
 5. Validate the elements in the ValidityInfo structure, i.e. verify that
    - the 'signed' date is within the validity period of the certificate in the MSO header;
    - the current timestamp shall be equal or later than the ‘validFrom’ element;
    - the 'validUntil' element shall be equal or later than the current timestamp

#### Validation example

> The X509 Certificates MUST be validated alone, expiration, revocation, using python cryptography x509.
In the example below the certificate is invalid since it is expired

````
import binascii 
import cbor2

from pycose.keys import EC2Key, CoseKey
from pycose.messages import Sign1Message


BIN_ISSUED_MDOC = binascii.unhexlify(ISSUED_MDOC)
do = cbor2.loads(BIN_ISSUED_MDOC)

# do
# {'version': '1.0', 'documents': ..., 'status': 0}

# here the mDocs
do['documents']

# do['documents'][0].keys()
# dict_keys(['docType', 'issuerSigned', 'deviceSigned']

# {'docType': 'org.iso.18013.5.1.mDL', 'issuerSigned': {'nameSpaces': {'org.iso.18013.5.1': [ ...], }, 'issuerAuth': ...}

# do['documents'][0]['issuerSigned']['nameSpaces']['org.iso.18013.5.1'][1]
# CBORTag(24, b'\xa4hdigestID\x03frandomX \xb2?b~\x89\x99\xc7\x06\xdf\x0c\nN\xd9\x8a\xd7J\xf9\x88\xafa\x9bK\xb0x\xb8\x90XU?Da]qelementIdentifierjissue_datelelementValue\xd9\x03\xecj2019-10-20

# here the MSO of the first document
ia = do['documents'][0]['issuerSigned']['issuerAuth']

key = CoseKey.from_dict(cbor2.loads(cbor2.loads(ia[2]).value)['deviceKeyInfo']['deviceKey'])

# TAG 18 identifies the COSE_Sign1 objects

# TAG18 = b'\xd2'
# decoded = Sign1Message.decode(TAG18 + b'\x84C\xa1\x01&' + BIN_ISSUED_MDOC.split(b'\x84C\xa1\x01&')[1].split(b'ldeviceSigned')[0])

# OR BETTER
decoded = Sign1Message.decode(cbor2.dumps(cbor2.CBORTag(18, value=ia)))
# decoded.key = key
# decoded.verify_signature()

# x509 certificate chain is here
decoded.uhdr

# Validate the X509 certificate chain -> its's not a chain but a single certificate in this example, then this won't work
from certvalidator import CertificateValidator
cert_validator = CertificateValidator(list(decoded.uhdr.values())[0])
cert_validator.validate_usage({'digital_signature'})

# get the public key after having validated the chain
import cryptography
der_certificate = cryptography.x509.load_der_x509_certificate(list(decoded.uhdr.values())[0])

# <cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey>
_key = der_certificates.public_key()

# PEM format
# der_certificates.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM)

# using CWT for kwy (unfortunately it doesn't support cbor Tag24)
# import cwt
# from cwt import Claims, COSEKey
# public_key = COSEKey.from_pem(pem, kid="issuer-01")
# 

COSEKEY_HAZMAT_CRV_MAP = {
    "secp256r1": "P_256"
}


# since _key.curve.name == secp256r1
key = EC2Key(crv=COSEKEY_HAZMAT_CRV_MAP[_key.curve.name], x=_key.public_numbers().x.to_bytes(32, 'big'))

decoded.key = key
decoded.verify_signature()
````


