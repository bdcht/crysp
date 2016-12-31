# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2008 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *
from crysp.utils.operators import rol,ror

from crysp.padding import MDpadding

#------------------------------------------------------------------------------
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
                r = i//16
                T = rol(a+self.ft[r](b,c,d)+W[i]+self.K[r],self.st[r][i%4])
                a = d
                d = c
                c = b
                b = T
            self.H[0] += a
            self.H[1] += b
            self.H[2] += c
            self.H[3] += d
        return b''.join([pack(h) for h in self.H])

#------------------------------------------------------------------------------
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
                r = i//16
                T = b+rol(a+self.ft[r](b,c,d)+W[i]+self.K[i],self.st[r][i%4])
                a = d
                d = c
                c = b
                b = T
            self.H[0] += a
            self.H[1] += b
            self.H[2] += c
            self.H[3] += d
        return b''.join([pack(h) for h in self.H])

#------------------------------------------------------------------------------
from crysp.poly import Poly
from crysp.padding import Nullpadding
from crysp.utils.operators import concat

Q = [0x7311c2812425cfa0,
     0x6432286434aac8e7,
     0xb60450e9ef68b7c1,
     0xe8fb23908d9f06f1,
     0xdd2e76cba691e5bf,
     0x0cd0d63b2c30bc41,
     0x1f8ccf6823058f8a,
     0x54e5ed5b88e3775d,
     0x4ad12aae0a6d6031,
     0x3e7f16bb88222e0d,
     0x8af8671d3fb50c2c,
     0x995ad1178bd25c31,
     0xc878c1dd04c4b633,
     0x3b72066c7a1552ac,
     0x0d6f3522631effcb]

rin = [10,  5, 13, 10, 11, 12,  2,  7, 14, 15,  7, 13, 11,  7,  6, 12]
lin = [11, 24,  9, 16, 15,  9, 27, 15,  6,  2, 29,  8, 15,  5, 31,  9]

class MD6(object):
    def __init__(self,d=512,Key=b'',L=0):
        self.size = d
        self.chunksize = 1024
        self.blocksize = 3*self.chunksize
        self.wsize = 64
        r = 40+(d//4)
        if Key: r = max(80,r)
        self.keylen = len(Key)
        Key = Key[:64].ljust(64,b'\0')
        self.K = Poly(struct.unpack('>8Q',Key),self.wsize)
        self.rounds = r
        self.L = L

    def __call__(self,M,bitlen=None):
        l = 0
        while 1:
            l += 1
            if l==self.L+1: return self.SEQ(M,bitlen)
            M = self.PAR(l,M,bitlen)
            if len(M)==128:
                h = Bits(M)>>(1024-self.size)
                h.size = self.size
                return h.bytes()

    def SEQ(self,M,bitlen=None):
        pad = Nullpadding(3072)
        B = [struct.unpack('>48Q',X) for X in pad.iterblocks(M,bitlen=bitlen)]
        j = len(B)
        z = 0
        d,keylen,L,r = self.size,self.keylen,self.L,self.rounds
        V = Bits(d,12)//Bits(keylen,8)//Bits(0,16)//Bits(z,4)//Bits(L,8)//Bits(r,12)//Bits(0,4)
        C = Poly(0,64,dim=16)
        W = Poly(Q,64,dim=89)//Poly(self.K,64)
        W.dim = 89
        W[24]  = V
        U = (self.L+1)<<56
        for i in range(j):
            if i==(j-1):
                V[20:36]=pad.padcnt
                V[36:40]=Bits(1,4)
                W[24]  = V
            W[23] = U+i
            W[25:41] = C
            W[41:89] = B[i]
            C = self.f(W)
        h = concat([c for c in C[::-1]])
        h.size = self.size
        return pack(h,'>L')

    def PAR(self,l,M,bitlen=None):
        pad = Nullpadding(4096)
        B = [struct.unpack('>64Q',X) for X in pad.iterblocks(M,bitlen=bitlen)]
        j = len(B)
        z = 1 if j==1 else 0
        d,keylen,L,r = self.size,self.keylen,self.L,self.rounds
        V = Bits(d,12)//Bits(keylen,8)//Bits(0,16)//Bits(z,4)//Bits(L,8)//Bits(r,12)//Bits(0,4)
        C = []
        W = Poly(Q,64)//Poly(self.K,64)
        W.dim = 89
        W[24]  = V
        for i in range(j):
            if i==(j-1):
                V[20:36]=pad.padcnt
                W[24]  = V
            U = (l<<56)+i
            W[23]  = U
            W[25:89] = B[i]
            C.append(self.f(W))
        Ml = concat(C)
        return b''.join((pack(c,'>L') for c in Ml))

    def f(self,N):
        C = Poly(0,64,dim=16)
        n = N.dim
        t = 16*self.rounds
        t0,t1,t2,t3,t4 = 17,18,21,31,67
        A = N//Poly(0,64,dim=t)
        S = Bits(0x0123456789abcdef,64)
        j = 0
        for i in range(n,n+t):
            x = S^A.e(i-n)^A.e(i-t0)
            x = x^(A.e(i-t1) & A.e(i-t2))^(A.e(i-t3) & A.e(i-t4))
            x = x^(x>>rin[j])
            A[i] = x^(x<<lin[j])
            j += 1
            if j==16:
                S = rol(S,1)^(S&0x7311c2812425cfa0)
                j=0
        return A[-16:]
