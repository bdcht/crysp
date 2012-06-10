#!/usr/bin/env python

from crysp.wb import *

K = Bits(a2b_hex("0123456789ABCDEF"))
b1 = Bits("Now is t")
b2 = Bits("he time ")
b3 = Bits("for"+"\5"*5)

KT = []
for r in range(16):
    s,t = table_rKT(r,K)
    KT.append(t)

WT = WhiteDES(KT,table_M1(),table_M2()[0],table_M3())

c = WT.enc("Now is the time for")
assert c == hex(enc(K,b1)//enc(K,b2)//enc(K,b3))
