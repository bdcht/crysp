# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2008-2013 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *
from crysp.poly import *
from crysp.utils.operators import ror
from crysp.sha import SHA2
from crysp.padding import Blakepadding

PI= [0x243F6A8885A308D3,
     0x13198A2E03707344,
     0xA4093822299F31D0,
     0x082EFA98EC4E6C89,
     0x452821E638D01377,
     0xBE5466CF34E90C6C,
     0xC0AC29B7C97C50DD,
     0x3F84D5B5B5470917,
     0x9216D5D98979FB1B,
     0xD1310BA698DFB5AC,
     0x2FFD72DBD01ADFB7,
     0xB8E1AFED6A267E96,
     0xBA7C9045F12C7F99,
     0x24A19947B3916CF7,
     0x0801F2E2858EFC16,
     0x636920D871574E69,
    ]

sigma = [[ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15],
         [14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3],
         [11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4],
         [ 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8],
         [ 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13],
         [ 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9],
         [12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11],
         [13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10],
         [ 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5],
         [10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0],
        ]

#------------------------------------------------------------------------------
class Blake(object):
    def __init__(self,size):
        self.size = size
        assert size in (224,256,384,512)
        self.blocksize = 1024 if size>256 else 512
        self.wsize = 64 if size>256 else 32
        self.outlen = self.size//8

    def initstate(self,salt=0):
        c64 = Poly(PI,size=64)
        if self.size>256:
            self.c = c64
            self.rounds = 16
        else:
            c64.dim = 8
            self.c = c64.split(32)
            for i in range(0,16,2):
                self.c.ival[i:i+2] = self.c.ival[i+1],self.c.ival[i]
            self.rounds = 14
        self.IV  = Poly([x.int() for x in SHA2(self.size).H],self.wsize)
        self.padmethod = Blakepadding(self.size)
        self.salt = Poly(salt,self.wsize*4).split(self.wsize)
        self.salt.ival.reverse()
        self.H = Poly(self.IV)

    def iterblocks(self,M,bitlen=None,padding=False):
        fmt = '>16L' if self.wsize==32 else '>16Q'
        for B in self.padmethod.iterblocks(M,bitlen=bitlen,padding=padding):
            W = struct.unpack(fmt,B)
            yield [Bits(w,self.wsize) for w in W]

    def __call__(self,M,s=0,bitlen=None):
        self.initstate(salt=s)
        return self.update(M,bitlen=bitlen,padding=True)

    def update(self,M,bitlen=None,padding=False):
        def G(W,r,i,v,ja,jb,jc,jd):
            ii = i+i
            p,q = sigma[r%10][ii:ii+2]
            xx = (32,25,16,11) if self.size>256 else (16,12,8,7)
            a,b,c,d = (x for x in v[ja,jb,jc,jd])
            a = a+b+(W[p]^self.c.e(q))
            d = ror(d^a,xx[0])
            c = c+d
            b = ror(b^c,xx[1])
            a = a+b+(W[q]^self.c.e(p))
            d = ror(d^a,xx[2])
            c = c+d
            b = ror(b^c,xx[3])
            v[ja,jb,jc,jd] = a,b,c,d
        for W in self.iterblocks(M,bitlen=bitlen,padding=padding):
            # initialize v[0...15]:
            v = Poly(0,self.wsize,dim=16)
            v[0:8] = self.H
            s = self.salt
            # counter convention is dumb: t[0] is the *low* wsize part
            t0,t1 = Bits(self.padmethod.bitcnt,2*self.wsize).split(self.wsize)
            polyt = Poly([t0,t0,t1,t1],self.wsize)
            v[8:12] = s^self.c[0:4]
            v[12:16] = polyt^self.c[4:8]
            for r in range(self.rounds):
                G(W,r,0,v,0,4,8,12)
                G(W,r,1,v,1,5,9,13)
                G(W,r,2,v,2,6,10,14)
                G(W,r,3,v,3,7,11,15)
                G(W,r,4,v,0,5,10,15)
                G(W,r,5,v,1,6,11,12)
                G(W,r,6,v,2,7,8,13)
                G(W,r,7,v,3,4,9,14)
            self.H[0:4] ^= (s^v[0:4]^v[8:12])
            self.H[4:8] ^= (s^v[4:8]^v[12:16])
        return b''.join([pack(h,'>L') for h in self.H])[:self.outlen]

blake224 = Blake(224)
blake256 = Blake(256)
blake384 = Blake(384)
blake512 = Blake(512)

#------------------------------------------------------------------------------
from crysp.padding import Nullpadding

class Blake2(Blake):

    def initstate(self,salt=b'',pers=b'',keylen=0,**kargs):
        super(Blake2,self).initstate(0)
        self.padmethod = Nullpadding(self.blocksize)
        self.outlen = kargs.get('outlen',self.outlen)
        self.rounds = 12 if self.size>256 else 10
        l = self.wsize//4
        if salt is b'': salt = b'\0'*l
        if pers is b'': pers = b'\0'*l
        self.keylen=keylen
        assert 0<self.outlen<=self.wsize
        assert self.keylen<=self.wsize
        self.treeinit(**kargs)
        self.paramblock(salt,pers)

    def paramblock(self,salt,pers):
        P = pack(Poly([self.outlen,self.keylen,self.fanout,self.depth],size=8))
        P += pack(self.leafl)
        P += pack(self.noffset)
        P += pack(Poly([self.ndepth,self.inner],size=8))
        if self.size==512: P += b'\0'*14
        P += salt+pers
        self.P = Poly(Bits(P,bitorder=1).split(self.wsize),self.wsize)
        self.H = self.IV ^ self.P

    def treeinit(self,fanout=1,depth=1,leafl=0,noffset=0,ndepth=0,inner=0,**kargs):
        self.fanout = fanout
        self.depth = depth
        self.leafl = Bits(leafl,32)
        self.noffset = Bits(noffset,64 if self.size==512 else 48)
        self.ndepth = ndepth
        self.inner = inner

    def iterblocks(self,M,padding=False):
        g = self.padmethod.iterblocks(M,padding=padding)
        blk = next(g)
        while (blk):
            try: #forsee last block:
                nextblk = next(g)
            except StopIteration:
                # set f0 finalization flag (blk is last)
                self.f[0]= -1
                nextblk = None
            # input words are now in little-endian:
            yield Bits(blk,bitorder=1).split(self.wsize)
            blk = nextblk

    def __call__(self,M,**kargs):
        self.initstate(**kargs)
        return self.update(M,padding=True)

    def update(self,M,padding=False):
        def G(W,r,i,v,ja,jb,jc,jd):
            ii = i+i
            p,q = sigma[r%10][ii:ii+2]
            xx = (32,24,16,63) if self.size>256 else (16,12,8,7)
            a,b,c,d = (x for x in v[ja,jb,jc,jd])
            a = a+b+W[p]
            d = ror(d^a,xx[0])
            c = c+d
            b = ror(b^c,xx[1])
            a = a+b+W[q]
            d = ror(d^a,xx[2])
            c = c+d
            b = ror(b^c,xx[3])
            v[ja,jb,jc,jd] = a,b,c,d
        # finalization flags f0,f1:
        self.f = Poly([0,0],self.wsize)
        for W in self.iterblocks(M,padding=padding):
            v = Poly(0,self.wsize,dim=16)
            v[0:8] = self.H
            v[8:12] = self.IV[0:4]
            # counter of *bytes*, in little-endian
            t = Bits(self.padmethod.bitcnt//8,2*self.wsize).split(self.wsize)
            v[12:14] = Poly(t,self.wsize)^self.IV[4:6]
            v[14:16] = self.f^self.IV[6:8]
            for r in range(self.rounds):
                G(W,r,0,v,0,4,8,12)
                G(W,r,1,v,1,5,9,13)
                G(W,r,2,v,2,6,10,14)
                G(W,r,3,v,3,7,11,15)
                G(W,r,4,v,0,5,10,15)
                G(W,r,5,v,1,6,11,12)
                G(W,r,6,v,2,7,8,13)
                G(W,r,7,v,3,4,9,14)
            self.H = self.H^(v[0:8]^v[8:16])
        # output hash string in little endian:
        return b''.join([pack(h) for h in self.H])[:self.outlen]

blake2b = Blake2(512)
blake2s = Blake2(256)
