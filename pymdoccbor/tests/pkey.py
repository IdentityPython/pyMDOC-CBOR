from pycose.keys import EC2Key

encoded_pkey = b'\xa6\x01\x02\x03& \x01!X \x8d%C\x91\xe8\x17A\xe1\xc2\xc1\'J\xa7\x1e\xe6J\x03\xc4\xc9\x8a\x91 hV\xcd\x10yb\x9f\xf7\xbe\x9a"X H\x8a\xc3\xd4\xc2\xea\x9bX\x9d\x9d\xf1~\x0c!\x92\xda\xfd\x02s\x0ci\xee\x190i\x88J\xddt\x14\x03\x95#X \xcd\xe1^\x92\xc8z\xd9&&\x0f\x0c\xbd\x8f4r}z\x03\x83\xe0\xf2\x8e\xcc\x04\x13M\xe1\xafXH\xcbT'

PKEY = EC2Key.decode(encoded_pkey)