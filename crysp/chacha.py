# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2009 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *
from crysp.poly import Poly
from crysp.utils.operators import *
from crysp import salsa20

cM    = salsa20.rMinv
cMinv = salsa20.rM
rM    = [0,5,10,15,1,6,11,12,2,7,8,13,3,4,9,14]
rMinv = [rM.index(x) for x in range(16)]

class Chacha(salsa20.Salsa20):

    def __init__(self,K=None,rounds=8):
        self.K = K
        self.p = Poly(0,size=32,dim=16)
        if K is not None:
            assert isinstance(K,Bits) and K.size in (128,256)
            self.K = K.split(128)
            consts = salsa20.sigma
            if len(self.K)==1:
                self.K.append(self.K[0])
                consts = salsa20.tau
            self.p[0:4] = consts
            self.p[4:8] = self.K[0].split(32)
            self.p[8:12] = self.K[1].split(32)
        assert rounds>0 and rounds&1==0
        self.dround = rounds>>1

    def keystream(self,v):
        assert self.K is not None
        assert isinstance(v,Bits) and v.size==64
        self.p[14:16] = v.split(32)
        maxlen = 1<<64
        i = 0
        while i<maxlen:
            self.p[12:14] = (i&0xffffffff,i>>32)
            yield self.core(self.p,dround=self.dround)
            i += 1

    def quarterround(self,y):
        a,b,c,d = y[0],y[1],y[2],y[3]
        a += b; d ^= a; d = rol(d,16)
        c += d; b ^= c; b = rol(b,12)
        a += b; d ^= a; d = rol(d, 8)
        c += d; b ^= c; b = rol(b, 7)
        return concat([a,b,c,d])

    def rowround(self,y):
        yM = y[rM]
        z = concat([self.quarterround(yM[i:i+4]) for i in range(0,16,4)])
        return z[rMinv]

    def columnround(self,x):
        return self.rowround(x[cM])[cMinv]

