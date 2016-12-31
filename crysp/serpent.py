# This code is part of crysp
# Copyright (C) 2009 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *
from crysp.utils.operators import ror,rol,concat

# -----------------------------------------------------------------------------
# Serpent-1 block cipher primitive
class Serpent(object):
    size = 128

    def __init__(self,K):
        self.K = Bits(K,bitorder=1)
        if len(self.K)<256:
            self.K = self.K//Bits(1,1)
        self.K.size = 256
        # key schelule:
        prekey = []
        phi = Bits(0x9e3779b9,32)
        for p in range(0,256,32):
            prekey.append(self.K[p:p+32])
        for i in range(132):
            wi = rol((prekey[-8]^prekey[-5]^prekey[-3]^prekey[-1]^phi^i),11)
            prekey.append(wi)
        self.keys = _keysched(prekey)

    def enc(self,M):
        assert len(M)==16
        R = Bits(M,bitorder=1)
        B = R
        for i in range(31):
            B = _L(_S(i%8,B^self.keys[i]))
        B = _S(31%8,B^self.keys[31])^self.keys[32]
        C = B
        return pack(C)

    def dec(self,C):
        assert len(C)==16
        R = Bits(C,bitorder=1)
        B = R
        B = _Sinv(31%8,B^self.keys[32])^self.keys[31]
        for i in range(30,-1,-1):
            B = _Sinv(i%8,_Linv(B))^self.keys[i]
        M = B
        return pack(M)

# Serpent internals:
#-------------------

def _S(i,X):
    assert 0<=i<8
    assert X.size==128
    boxes = [
       [ 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12],
       [15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4],
       [ 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2],
       [ 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14],
       [ 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13],
       [15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1],
       [ 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0],
       [ 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6],
    ]
    Sx = [Bits(boxes[i][x],4) for x in _IP(X).split(4)]
    return _FP(concat(Sx))

def _Sinv(i,X):
    assert 0<=i<8
    assert X.size==128
    boxes = [
       [13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2],
       [ 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0],
       [12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7],
       [ 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1],
       [ 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1],
       [ 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0],
       [15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11],
       [ 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2],
    ]
    Sx = [Bits(boxes[i][x],4) for x in _IP(X).split(4)]
    return _FP(concat(Sx))

def _IP(X):
    assert X.size==128
    table = [
        0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
        4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
        8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
        12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
        16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
        20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
        24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
        28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
    ]
    return X[table]

def _FP(X):
    assert X.size==128
    table = [
        0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
        64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
        1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
        65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
        2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
        66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
        3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
        67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
    ]
    return X[table]

def _keysched(prekey):
    keys = []
    k = 8
    for r in range(35,2,-1):
        Kr = concat(prekey[k:k+4])
        k+=4
        keys.append(_S(r%8,Kr))
    assert len(keys)==33
    return keys

def _L(X):
    assert X.size==128
    X = X.split(32)
    X[0] = rol(X[0],13)
    X[2] = rol(X[2],3)
    X[1] = X[1]^X[0]^X[2]
    X[3] = X[3]^X[2]^(X[0]<<3)
    X[1] = rol(X[1],1)
    X[3] = rol(X[3],7)
    X[0] = X[0]^X[1]^X[3]
    X[2] = X[2]^X[3]^(X[1]<<7)
    X[0] = rol(X[0],5)
    X[2] = rol(X[2],22)
    return concat(X)

def _Linv(X):
    assert X.size==128
    X = X.split(32)
    X[2] = ror(X[2],22)
    X[0] = ror(X[0],5)
    X[2] = X[2]^X[3]^(X[1]<<7)
    X[0] = X[0]^X[1]^X[3]
    X[3] = ror(X[3],7)
    X[1] = ror(X[1],1)
    X[3] = X[3]^X[2]^(X[0]<<3)
    X[1] = X[1]^X[0]^X[2]
    X[2] = ror(X[2],3)
    X[0] = ror(X[0],13)
    return concat(X)
