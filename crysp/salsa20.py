# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2012 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.poly import *
from crysp.utils.operators import *


_rM    = [0,1,2,3,5,6,7,4,10,11,8,9,15,12,13,14]
_rMinv = [_rM.index(x) for x in range(16)]

_cM    = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
_cMinv = [_cM.index(x) for x in range(16)]

def quarterround(y):
    z1 = y[1]^rol(y[0]+y[3],7 )
    z2 = y[2]^rol(z1  +y[0],9 )
    z3 = y[3]^rol(z2  +z1  ,13)
    z0 = y[0]^rol(z3  +z2  ,18)
    return concat([z0,z1,z2,z3])

def rowround(y):
    yM = y[_rM]
    z = concat([quarterround(yM[i:i+4]) for i in range(0,16,4)])
    return z[_rMinv]

def columnround(x):
    return rowround(x[_cM])[_cMinv]

def doubleround(x):
    return rowround(columnround(x))

def _Salsa20(X,dround=10):
    Z = X
    for n in range(dround):
        Z = doubleround(Z)
    return X+Z

_sigma = [Bits(x,bitorder=1) for x in ['expa', 'nd 3', '2-by', 'te k']]
_tau   = [Bits(x,bitorder=1) for x in ['expa', 'nd 1', '6-by', 'te k']]

class Salsa20(object):

    def __init__(self,K=None,rounds=20):
        self.K = K
        self.p = Poly(0,size=32,dim=16)
        if K is not None:
            assert isinstance(K,Bits) and K.size in (128,256)
            self.K = K.split(128)
            consts = _sigma
            if len(self.K)==1:
                self.K.append(self.K[0])
                consts = _tau
            self.p[0,5,10,15] = consts
            self.p[1:5] = self.K[0].split(32)
            self.p[11:15] = self.K[1].split(32)
        assert rounds>0 and rounds&1==0
        self.dround = rounds>>1

    def hash(self,m):
        L = Bits(m,bitorder=1).split(32)
        X = Poly([x.int() for x in L],size=32)
        return ''.join([pack(z) for z in _Salsa20(X)])

    def keystream(self,v):
        assert self.K is not None
        assert isinstance(v,Bits) and v.size==64
        self.p[6:8] = v.split(32)
        maxlen = 1L<<64
        i = 0L
        while i<maxlen:
            self.p[8:10] = (i&0xffffffffL,i>>32)
            yield _Salsa20(self.p,dround=self.dround)

    def enc(self,v,m):
        C = []
        p = 0
        for x in self.keystream(v):
            b = m[p:p+64]
            if len(b)==0: break
            x = x.split(8)
            x.dim = len(b)
            c = x^Poly(b)
            C.append(''.join([chr(x) for x in c.ival]))
            p += 64
        return ''.join(C)

    def dec(self,v,c):
        return self.enc(v,c)
