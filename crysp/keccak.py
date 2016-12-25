# -*- coding: latin-1 -*-

# This code is part of crysp
# Copyright (C) 2013 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *

from io import BytesIO

RC = list(range(24))
# Constants:
RC[ 0] = Bits(0x0000000000000001,64)
RC[ 1] = Bits(0x0000000000008082,64)
RC[ 2] = Bits(0x800000000000808A,64)
RC[ 3] = Bits(0x8000000080008000,64)
RC[ 4] = Bits(0x000000000000808B,64)
RC[ 5] = Bits(0x0000000080000001,64)
RC[ 6] = Bits(0x8000000080008081,64)
RC[ 7] = Bits(0x8000000000008009,64)
RC[ 8] = Bits(0x000000000000008A,64)
RC[ 9] = Bits(0x0000000000000088,64)
RC[10] = Bits(0x0000000080008009,64)
RC[11] = Bits(0x000000008000000A,64)
RC[12] = Bits(0x000000008000808B,64)
RC[13] = Bits(0x800000000000008B,64)
RC[14] = Bits(0x8000000000008089,64)
RC[15] = Bits(0x8000000000008003,64)
RC[16] = Bits(0x8000000000008002,64)
RC[17] = Bits(0x8000000000000080,64)
RC[18] = Bits(0x000000000000800A,64)
RC[19] = Bits(0x800000008000000A,64)
RC[20] = Bits(0x8000000080008081,64)
RC[21] = Bits(0x8000000000008080,64)
RC[22] = Bits(0x0000000080000001,64)
RC[23] = Bits(0x8000000080008008,64)


#parameters of Keccac-f permutations
class Keccak(object):
    def __init__(self,_b=1600,_c=576,**kargs):
        b = kargs.get('b',_b)
        c = kargs.get('c',_c)
        r = kargs.get('r',b-c)
        self.outlen = kargs.get('len',None)
        if not (b == r+c):
            if 'b' in kargs and 'r' in kargs:
                c = b-r
            if 'r' in kargs and 'c' in kargs:
                b = r+c
        assert b == r+c
        assert b in (25,50,100,200,400,800,1600)
        self.b = b
        self.w = b//25 # w is supposed to fit the CPU word/register length.
        l = {1:0,2:1,4:2,8:3,16:4,32:5,64:6}[self.w]
        self.n = 12+2*l
        self.setrate(r)
        self.duplexing = False

    def setrate(self,r):
        assert r<=1536
        # usual rate belongs to (576,832,1024,1088,1152,1344)
        #assert r%self.w==0
        self.r = r
        self.c = self.b-self.r

    def f(self,A) :
        global RC
        for i in range(0,self.n):
            A = Round(A,RC[i][:self.w])
        return A

    def __call__(self,M,bitlen=None,r=None):
        # create state (null) :
        S = State(self.w)
        # set rate:
        if r is None:
            assert self.r
            r = self.r
        else:
            self.setrate(r)

        #Absorbing phase
        for Pi in self.iterblocks(M,bitlen):
            Ps = State(self.w).load(Pi)
            S = self.f(S^Ps)

        #Squeezing phase
        Z = S.dump(r)
        while len(Z)<self.outlen:
            S = self.f(S)
            Z = Z//S.dump(r)
        return pack(Z[:self.outlen])

    def iterblocks(self,M,bitlen=None):
        needed = len(M)*8
        # handle NIST MSB alignment to Keccak LSB alignment for last byte
        # (see Keccak SHA-3 submission §6.1):
        if bitlen:
            assert bitlen<=needed
            needed = bitlen
            if not self.duplexing:
                b = Bits(M[-1:],size=needed%8)[::-1]
                M = M[:needed//8]+newbytes([b.ival])
        r = self.r
        br,rr = divmod(r,8)
        P = BytesIO(M)
        # init iterator loop:
        Pi = P.read(br)
        Pb = Bits(0,size=0)
        while len(Pi)>0:
            # input message bitstream buffer:
            Pb =  Pb//Bits(Pi,bitorder=1)
            if len(Pb)>=needed:
                Pb.size=needed
                P.read() # consume all stream to exit loop
            if len(Pb)>=r:
                yield Pb[:r]
                needed -= r
                Pb = Pb[r:]
            Pi = P.read(br)
        # pad10*1 (with little-endian convention) :
        Pb = Pb//Bits(1)//Bits(0,size=r-len(Pb)-2)//Bits(1)
        yield Pb

    # Duplex construction (see "Cryptographic Sponge Functions", http://sponge.noekeon.org)
    def duplex(self,m,bitlen=None,outlen=None):
        self.duplexing = True
        L = [x for x in self.iterblocks(m,bitlen)]
        assert len(L)==1
        if outlen==None: outlen=self.r
        if not hasattr(self,'_S'):
            self._S = State(self.w)
        self._S = self.f(self._S^State(self.w).load(L[0]))
        return pack(self._S.dump(outlen))

# internal state of the Keccac-f permutation is of length b.
# It is organized in 3 dimensions (x,y,z) \in Z^5 x Z^5 x Z^w
# with linear bit index i = z + w(5y+x)
# A lane (of length w) is a set of bits with identical (x,y) indices.
class State(object):
    def __init__(self,w):
        self.w = w
        self.lanes = []
        for l in range(25):
            self.lanes.append(Bits(0,w))

    def __getitem__(self,xy):
        x,y = xy
        x,y = x%5,y%5
        reg = self.lanes[5*y+x]
        return reg

    def __setitem__(self,xy,v):
        x,y = xy
        x,y = x%5,y%5
        self.lanes[5*y+x] = v

    # load r-block into State (r<b)
    def load(self,B):
        w = self.w
        i = 0
        for l in range(25):
            bl = B[i:i+w]
            bl.size = w
            self.lanes[l] = bl
            i += w
        # return self to allow State().load() instance init
        return self

    def dump(self,r):
        assert r<=(25*self.w)
        i = 0
        z = Bits(0,size=0)
        while (i<25 and len(z)<=r):
            z = z//self.lanes[i]
            i += 1
        z.size = r
        return z

    def __xor__(self,s):
        assert s.w == self.w
        sr = State(self.w)
        for l in range(25):
            sr.lanes[l] = self.lanes[l]^s.lanes[l]
        return sr


def Round(A,RCi):
    # r(x,y) table:
    r = {
      (3,2): 25, (4,2): 39, (0,2):  3, (1,2): 10, (2,2): 43,
      (3,1): 55, (4,1): 20, (0,1): 36, (1,1): 44, (2,1):  6,
      (3,0): 28, (4,0): 27, (0,0):  0, (1,0):  1, (2,0): 62,
      (3,4): 56, (4,4): 14, (0,4): 18, (1,4):  2, (2,4): 61,
      (3,3): 21, (4,3):  8, (0,3): 41, (1,3): 45, (2,3): 15,
    }
    C = [0]*5
    D = [0]*5
    #θ step
    for x in range(0,5):
          C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
    for x in range(0,5):
          D[x] = C[(x-1)%5] ^ rot(C[(x+1)%5],1)
    for x in range(0,5):
        for y in range(0,5):
            A[x,y] = A[x,y] ^ D[x]
    #ρ and π steps
    B = State(A.w)
    for x in range(0,5):
        for y in range(0,5):
            B[y,2*x+3*y] = rot(A[x,y], r[x,y])
    #χ step
    for x in range(0,5):
        for y in range(0,5):
            A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])
    #ι step
    A[0,0] = A[0,0] ^ RCi
    return A

def rot(l,n):
    w = len(l)
    sl = n%w
    sr = w-sl
    return (l<<sl)|(l>>sr)


sha3_224 = Keccak(b=1600,c=448,len=224)
sha3_256 = Keccak(b=1600,c=512,len=256)
sha3_384 = Keccak(b=1600,c=768,len=384)
sha3_512 = Keccak(b=1600,c=1024,len=512)

