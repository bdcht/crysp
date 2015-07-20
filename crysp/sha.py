# -*- coding: latin-1 -*-

# This code is part of crysp
# Copyright (C) 2008 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *
from crysp.utils.operators import rol,ror

import StringIO

Ch     = lambda x,y,z: z^(x&(y^z))
Parity = lambda x,y,z: x^y^z
Maj    = lambda x,y,z: (x&y)|(x&z)|(y&z)


class SHA1(object):
    def __init__(self,version=1):
        self.size = 160
        self.blocksize = 512
        self.wsize = 32
        assert version in (0,1)
        self.version = version
        # set functions and constants:
        self.ft = [Ch]*20+[Parity]*20+[Maj]*20+[Parity]*20
        self.K = [0x5a827999]*20 +\
                 [0x6ed9eba1]*20 +\
                 [0x8f1bbcdc]*20 +\
                 [0xca62c1d6]*20
        self.initstate()

    def initstate(self):
        H = [0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0]
        self.H = [Bits(v,self.wsize) for v in H]

    def padblock(self,m,bitlen=0):
        if bitlen==0: bitlen = len(m)*8
        n,r = divmod(bitlen,self.blocksize)
        countsize = self.wsize*2
        pad = Bits(1,1)//Bits(0,self.blocksize-r-1-countsize)
        return m+hex(pad)+pack(Bits(bitlen,countsize),'>L')

    def iterblocks(self,M):
        P = StringIO.StringIO(M)
        osize = self.blocksize/8
        fmt = '>16L' if self.wsize==32 else '>8Q'
        Pi = P.read(osize)
        bitlen = 0
        while len(Pi)==osize:
            W = struct.unpack(fmt,Pi)
            yield [Bits(w,self.wsize) for w in W]
            bitlen += self.blocksize
            Pi = P.read(osize)
        if len(Pi)>0:
            bitlen += len(Pi)*8
            Pi = self.padblock(Pi,bitlen)
            W = struct.unpack(fmt,Pi)
            yield [Bits(w,self.wsize) for w in W]

    def __call__(self,M):
        self.initstate()
        return self.update(self.padblock(M))

    def update(self,M):
        for W in self.iterblocks(M):
            a,b,c,d,e = self.H
            assert len(W)==16
            for t in range(16,80):
                w = rol(W[t-3]^W[t-8]^W[t-14]^W[t-16],1)
                W.append(w)
            for r in range(80):
                T = rol(a,5)+self.ft[r](b,c,d)+e+self.K[r]+W[r]
                e = d
                d = c
                c = rol(b,30)
                b = a
                a = T
            self.H[0] += a
            self.H[1] += b
            self.H[2] += c
            self.H[3] += d
            self.H[4] += e
        return ''.join([pack(h,'>L') for h in self.H])

class SHA2(object):
    def __init__(self,size,t=0):
        assert size in (224,256,384,512)
        self.size = size
        self.version = 2
        if t>0:
            assert self.size==512
            assert t in (224,256)
        # set functions and constants:
        if self.size  in (224,256):
            self.blocksize = 512
            self.wsize = 32
            self.Sigma_0 = lambda x,y,z: ror(x,2)^ror(x,13)^ror(x,22)
            self.Sigma_1 = lambda x,y,z: ror(x,6)^ror(x,11)^ror(x,25)
            self.sigma_0 = lambda x,y,z: ror(x,7)^ror(x,18)^ror(x,3)
            self.sigma_1 = lambda x,y,z: ror(x,17)^ror(x,19)^ror(x,10)
            self.K = [int(s,16) for s in '''
            428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
            d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
            e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
            983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
            27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
            a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
            19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
            748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
            '''.split()]
        elif self.size>256:
            self.blocksize = 1024
            self.wsize = 64
            self.Sigma_0 = lambda x,y,z: ror(x,28)^ror(x,34)^ror(x,39)
            self.Sigma_1 = lambda x,y,z: ror(x,14)^ror(x,18)^ror(x,41)
            self.sigma_0 = lambda x,y,z: ror(x,1)^ror(x,8)^ror(x,7)
            self.sigma_1 = lambda x,y,z: ror(x,19)^ror(x,61)^ror(x,6)
            self.K = [int(s,16) for s in '''
            428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc
            3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118
            d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2
            72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694
            e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65
            2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5
            983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4
            c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70
            27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df
            650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
            a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30
            d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8
            19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8
            391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3
            748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
            90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b
            ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178
            06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b
            28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c
            4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817
            '''.split()]
        self.initstate(t)

        def initstate(self,t=None):
            if t is not None: self.t = t
            t = self.t
            if self.size==224 or t==224:
                H = [
                     0xc1059ed8 if not t else 0x8C3D37C819544DA2,
                     0x367cd507 if not t else 0x73E1996689DCD4D6,
                     0x3070dd17 if not t else 0x1DFAB7AE32FF9C82,
                     0xf70e5939 if not t else 0x679DD514582F9FCF,
                     0xffc00b31 if not t else 0x0F6D2B697BD44DA8,
                     0x68581511 if not t else 0x77E36F7304C48942,
                     0x64f98fa7 if not t else 0x3F9D85A86A1D36C8,
                     0xbefa4fa4 if not t else 0x1112E6AD91D692A1,
                    ]
            elif self.size==256 or t==256:
                H = [
                     0x6a09e667 if not t else 0x22312194FC2BF72C,
                     0xbb67ea85 if not t else 0x9F555FA3C84C64C2,
                     0x3c6ef372 if not t else 0x2393B86B6F53B151,
                     0xa54ff53a if not t else 0x963877195940EABD,
                     0x510e527f if not t else 0x96283EE2A88EFFE3,
                     0x9b05688c if not t else 0xBE5E1E2553863992,
                     0x1f83d9ab if not t else 0x2B0199FC2C85B8AA,
                     0x5be0cd19 if not t else 0x0EB72DDC81C52CA2,
                    ]
            elif self.size==384:
                H = [
                     0xcbbb9d5dc1059ed8,
                     0x629a292a367cd507,
                     0x9159015a3070dd17,
                     0x152fecd8f70e5939,
                     0x67332667ffc00b31,
                     0x8eb44a8768581511,
                     0xdb0c2e0d64f98fa7,
                     0x47b5481dbefa4fa4,
                    ]
            elif self.size==512:
                H = [
                     0x6a09e667f3bcc908,
                     0xbb67ae8584caa73b,
                     0x3c6ef372fe94f82b,
                     0xa54ff53a5f1d36f1,
                     0x510e527fade682d1,
                     0x9b05688c2b3e6c1f,
                     0x1f83d9abfb41bd6b,
                     0x5be0cd19137e2179,
                    ]
            self.H = [Bits(v,self.wsize) for v in H]

