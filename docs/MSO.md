# Mobile Security Object

The MSO is encapsulated and signed by the untagged COSE_Sign1 structure 
as defined in RFC 8152  and identified as “IssuerAuth” in 8.2.1.1.2.2. 
Within the COSE_Sign1 structure, the ‘payload’ shall be  the 
‘MobileSecurityObject’ structure. The ‘external_aad’ field used in 
the ‘Sig_structure’ shall be a  bytestring of size zero. 


The MSO has the following CDDL structure: 

````
MobileSecurityObject = { 
 "digestAlgorithm" : tstr, ; Message digest algorithm used  "valueDigests" : ValueDigests, ; Array of digests of all data elements  "deviceKey" : DeviceKey, 
 "docType" : tstr, ; DocType as used in Documents  "validityInfo" : ValidityInfo 
} 
DeviceKey = COSE_Key ; Device key in COSE_Key as defined in RFC  8152 
ValueDigests = { 
 "nameSpaces" : NameSpacesDigests 
} 
NameSpacesDigests = { 
 + NameSpace => DigestIDs 
} 
DigestIDs = { 
 + DigestID => Digest 
} 
ValidityInfo = { 
 "signed" : tdate, 
 "validFrom" : tdate, 
 "validUntil" : tdate, 
 ? "expectedUpdate" : tdate 
} 
````


The ‘digestAlgorithm’ and ‘valueDigests’ are the digest algorithm identifier 
and the digests of the  data elements. 


The ‘deviceKey’ is the public key pair used for authentication. 
The ‘deviceKey’ element is encoded as an untagged COSE_Key 
element as specified in  RFC 8152. 


The ‘ValidityInfo’ structure contains information related to 
the validity of the MSO and its signature.


The “alg” element (RFC 8152) shall be included as an element in the 
protected header. Other elements  should not be present in the protected header.


The DS certificate shall be included as a ‘x5chain’ element as described 
in “draft-ietf-cose-x509-04”. It  shall be included as an 
unprotected header element. 


The input for the digest function is the binary data of the  IssuerSignedItem. 
Each IssuerSignedItem also contains a random value. 
This value shall be  different for each IssuerSignedItem and 
shall have a minimum length of 16 bytes. 


The mDL private key, which belongs to the mDL public key stored in 
the MSO, is used to authenticate the  mDL. 
It is also used to authenticate the response data contained in the 
DeviceSignedItems structure. 


## Presenter Authentication

The mDL authentication key pair consists of a public and a private key 
(SDeviceKey.Priv, SDeviceKey. Pub). The public key is accessible 
through the DeviceKey element in the MSO. 



