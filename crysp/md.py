# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2008 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *
from crysp.utils.operators import rol,ror


from crysp.padding import MDpadding

class MD4(object):
    def __init__(self):
        self.size = 128
        self.blocksize = 512
        self.wsize = 32
        # set functions and constants:
        f = lambda x,y,z: z^(x&(y^z))
        g = lambda x,y,z: (x&y)|(x&z)|(y&z)
        h = lambda x,y,z: x^y^z
        self.ft = [f,g,h]
        self.K = [0,0x5a827999,0x6ed9eba1]
        self.st = [(3,7,11,19),(3,5,9,13),(3,9,11,15)]
        self.initstate()

    def initstate(self):
        H = [0x67452301,0xefcdab89,0x98badcfe,0x10325476]
        self.H = [Bits(v,self.wsize) for v in H]
        self.padmethod = MDpadding(self.blocksize,self.wsize)

    def iterblocks(self,M,bitlen=None,padding=False):
        for B in self.padmethod.iterblocks(M,bitlen=bitlen,padding=padding):
            W = Bits(B,bitorder=1)
            yield W.split(self.wsize)

    def __call__(self,M,bitlen=None):
        self.initstate()
        return self.update(M,bitlen=bitlen,padding=True)

    def update(self,M,bitlen=None,padding=False):
        for W in self.iterblocks(M,bitlen=bitlen,padding=padding):
            a,b,c,d = self.H
            assert len(W)==16
            W.extend([W[i] for i in (0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15)])
            W.extend([W[i] for i in (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15)])
            for i in range(3*16):
                r = i/16
                T = rol(a+self.ft[r](b,c,d)+W[i]+self.K[r],self.st[r][i%4])
                a = d
                d = c
                c = b
                b = T
            self.H[0] += a
            self.H[1] += b
            self.H[2] += c
            self.H[3] += d
        return ''.join([pack(h) for h in self.H])

class MD5(MD4):
    def __init__(self):
        self.size = 128
        self.blocksize = 512
        self.wsize = 32
        # set functions and constants:
        f = lambda x,y,z: z^(x&(y^z))
        g = lambda x,y,z: f(z,x,y)
        h = lambda x,y,z: x^y^z
        i = lambda x,y,z: y^(x|~z)
        self.ft = [f,g,h,i]
        self.K = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
                  0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
                  0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
                  0x6b901122,0xfd987193,0xa679438e,0x49b40821,
                  0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
                  0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
                  0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
                  0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
                  0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
                  0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
                  0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
                  0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
                  0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
                  0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
                  0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
                  0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391]
        self.st = [(7,12,17,22),(5,9,14,20),(4,11,16,23),(6,10,15,21)]
        self.initstate()

    def update(self,M,bitlen=None,padding=False):
        for W in self.iterblocks(M,bitlen=bitlen,padding=padding):
            a,b,c,d = self.H
            assert len(W)==16
            W.extend([W[i] for i in (1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12)])
            W.extend([W[i] for i in (5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2)])
            W.extend([W[i] for i in (0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9)])
            for i in range(4*16):
                r = i/16
                T = b+rol(a+self.ft[r](b,c,d)+W[i]+self.K[i],self.st[r][i%4])
                a = d
                d = c
                c = b
                b = T
            self.H[0] += a
            self.H[1] += b
            self.H[2] += c
            self.H[3] += d
        return ''.join([pack(h) for h in self.H])
