#!/usr/bin/env python
from crysp.crc import *
from binascii import b2a_hex

D = {
        "": 0x0,
        "a": 0xe8b7be43L,
        "abc": 0x352441c2L,
        "message digest": 0x20159d7fL,
        "Toto": 0xB0FE0BCFL,
    }
l = max(map(len,D))
for (k,v) in D.iteritems():
    print ("crc32(%s)"%k).ljust(l+8)+" = %08s\t(test vector:%08s)"%(hex(crc32(k)),hex(v))


