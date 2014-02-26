#!/usr/bin/env python

from crysp.wb import *
from crysp.mode import ECB,CBC

K = "0123456789ABCDEF".decode('hex')
bK = Bits(K,64)
b1 = "Now is t"
b2 = "he time "
b3 = "for"+"\5"*5

KT = []
for r in range(16):
    s,t = table_rKT(r,bK)
    KT.append(t)

E  = DES(K)
WT = ECB(WhiteDES(KT,table_M1(),table_M2()[0],table_M3()))

c = WT.enc("Now is the time for")
assert c == E.enc(b1)+E.enc(b2)+E.enc(b3)

E = CBC(TDEA('12345678abcdabcd'), IV='tototiti')
c='\xd7+\x0c\xads\x8aX\xe3\xa5;1\xd0\xd2g^bS\x11\xd0\xd6\xf6\xcfA\xc8'
assert E.enc("CBC 3DES testing")[8:]==c


