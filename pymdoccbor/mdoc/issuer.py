import binascii
import cbor2
import logging

from pycose.keys import CoseKey
from typing import Union

from pymdoccbor.mso.issuer import MsoIssuer

logger = logging.getLogger('pymdoccbor')


class MdocCborIssuer:

    def __init__(self, private_key: Union[dict, CoseKey] = {}):
        self.version: str = '1.0'
        self.status: int = 0
        if private_key and isinstance(private_key, dict):
            self.private_key = CoseKey.from_dict(private_key)
        
        self.signed :dict = {}

    def new(
        self,
        data: dict,
        devicekeyinfo: Union[dict, CoseKey],
        doctype: str
    ):
        """
        create a new mdoc with signed mso
        """
        if isinstance(devicekeyinfo, dict):
            devicekeyinfo = CoseKey.from_dict(devicekeyinfo)
        else:
            devicekeyinfo: CoseKey = devicekeyinfo

        msoi = MsoIssuer(
            data=data,
            private_key=self.private_key
        )

        mso = msoi.sign()

        # TODO: for now just a single document, it would be trivial having
        # also multiple but for now I don't have use cases for this
        res = {
            'version': self.version,
            'documents': [
                {
                    'docType': doctype,  # 'org.iso.18013.5.1.mDL'
                    'issuerSigned': {
                        "nameSpaces": {
                            ns: [
                                cbor2.CBORTag(24, value={k: v}) for k, v in dgst.items()
                            ]
                            for ns, dgst in msoi.disclosure_map.items()
                        },
                        "issuerAuth": mso.encode()
                    },
                    'deviceSigned': {
                        # TODO
                    }
                }
            ],
            'status': self.status
        }
        
        self.signed = res
        return self.signed
    
    def dump(self):
        """
            returns bytes
        """
        return cbor2.dumps(self.signed)

    def dumps(self):
        """
            returns AF binary repr
        """
        return binascii.hexlify(cbor2.dumps(self.signed))
