# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2008 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.poly import *
from crysp.utils.operators import *

rM    = [0,1,2,3,5,6,7,4,10,11,8,9,15,12,13,14]
rMinv = [rM.index(x) for x in range(16)]

cM    = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
cMinv = [cM.index(x) for x in range(16)]

sigma = [Bits(x,bitorder=1) for x in [b'expa', b'nd 3', b'2-by', b'te k']]
tau   = [Bits(x,bitorder=1) for x in [b'expa', b'nd 1', b'6-by', b'te k']]

class Salsa20(object):

    def __init__(self,K=None,rounds=20):
        self.K = K
        self.p = Poly(0,size=32,dim=16)
        if K is not None:
            assert isinstance(K,Bits) and K.size in (128,256)
            self.K = K.split(128)
            consts = sigma
            if len(self.K)==1:
                self.K.append(self.K[0])
                consts = tau
            self.p[0,5,10,15] = consts
            self.p[1:5] = self.K[0].split(32)
            self.p[11:15] = self.K[1].split(32)
        assert rounds>0 and rounds&1==0
        self.dround = rounds>>1

    def hash(self,m):
        L = Bits(m,bitorder=1).split(32)
        X = Poly([x.int() for x in L],size=32)
        return b''.join([pack(z) for z in self.core(X)])

    def keystream(self,v):
        assert self.K is not None
        assert isinstance(v,Bits) and v.size==64
        self.p[6:8] = v.split(32)
        maxlen = 1<<64
        i = 0
        while i<maxlen:
            self.p[8:10] = (i&0xffffffff,i>>32)
            yield self.core(self.p,dround=self.dround)
            i += 1

    def enc(self,v,m):
        C = []
        p = 0
        for x in self.keystream(v):
            b = m[p:p+64]
            if len(b)==0: break
            x = x.split(8)
            x.dim = len(b)
            c = x^Poly(b)
            C.append(newbytes(c.ival))
            p += 64
        return b''.join(C)

    def dec(self,v,c):
        return self.enc(v,c)

    def quarterround(self,y):
        z1 = y[1]^rol(y[0]+y[3],7 )
        z2 = y[2]^rol(z1  +y[0],9 )
        z3 = y[3]^rol(z2  +z1  ,13)
        z0 = y[0]^rol(z3  +z2  ,18)
        return concat([z0,z1,z2,z3])

    def rowround(self,y):
        yM = y[rM]
        z = concat([self.quarterround(yM[i:i+4]) for i in range(0,16,4)])
        return z[rMinv]

    def columnround(self,x):
        return self.rowround(x[cM])[cMinv]

    def doubleround(self,x):
        return self.rowround(self.columnround(x))

    def core(self,X,dround=10):
        Z = X
        for n in range(dround):
            Z = self.doubleround(Z)
        return X+Z
