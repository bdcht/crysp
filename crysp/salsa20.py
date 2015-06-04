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

def salsa20_hash(m):
    L = Bits(m,bitorder=1).split(32)
    X = Poly([x.int() for x in L],size=32)
    Z = X
    for n in range(10):
        Z = doubleround(Z)
    return ''.join([pack(z) for z in (X+Z)])
