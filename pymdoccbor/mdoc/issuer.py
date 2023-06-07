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
                                cbor2.CBORTag(24, value=v) for v in dgst
                            ]
                            for ns, dgst in mso.disclosure_map.items()
                        },
                        'deviceSigned': {
                            # TODO
                        }
                    }
                }
            ],
            'status': self.status
        }

        return res
