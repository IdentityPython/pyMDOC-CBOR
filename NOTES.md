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

````python
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
    'issuerAuth': ->  Contains the mobile security object (MSO) for issuer data authentication, an Array of the elements below
        cbor({1: -7})
        {33: cbor tag( -17)}
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

#### `issuerAuth` with TAG 33

The `x5chain` element has the temporary identifer 33 registered in the IANA registry.

Please note: ISO 18013-5 uses draft not standards yet, like:

 - draft-ietf-cbor-date-tag-01
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

#### 

````
BIN_ISSUED_MDOC = binascii.unhexlify(ISSUED_MDOC)
do = cbor2.loads(BIN_ISSUED_MDOC)

# here the mDocs
do['documents']

# here the MSO of the first document
ia = do['documents'][0]['issuerSigned']['issuerAuth']

key = CoseKey.from_dict(cbor2.loads(cbor2.loads(ia[2]).value)['deviceKeyInfo']['deviceKey'])

from pycose.messages import Sign1Message

# TAG 18 identifies the COSE_Sign1 objects

TAG18 = b'\xd2'
decoded = Sign1Message.decode(TAG18 + b'\x84C\xa1\x01&' + BIN_ISSUED_MDOC.split(b'\x84C\xa1\x01&')[1].split(b'ldeviceSigned')[0])

# OR BETTER
decoded = Sign1Message.decode(cbor2.dumps(cbor2.CBORTag(18, value=ia)))
decoded.key = key
decoded.verify_signature()


mso = Sign1Message(
    phdr = cbor2.loads(ia[0]),
    payload = ia[2]
)
mso.key = key

````


