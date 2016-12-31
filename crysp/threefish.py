# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license

from crysp.bits import *
from crysp.utils.operators import *

# Threefish block cipher primitive provides enc/dec methods
# for encryption and decryption of one data block.
class Threefish(object):

    # sK (key) and sT (tweak) are typically byte strings,
    # but provided values can be integers, bitlist or Bits as well.
    # Length of sK determines Threefish block length,
    # (length of tweak must be 128 bits.)
    def __init__(self,sK,sT):
        # check input key and tweak:
        K = Bits(sK,bitorder=1)
        T = Bits(sT,bitorder=1)
        assert K.size in (256,512,1024)
        self.K = K
        assert T.size==128
        self.T = T
        # get 64-bits words and rounds:
        self.Nw = self.K.size//64
        self.Nr = 72 if self.Nw<16 else 80
        # set pi permutation and inverse:
        self.__pi={ 4: (0,3,2,1),
                    8: (2,1,4,7,6,5,0,3),
                   16: (0,9,2,13,6,11,4,15,10,7,12,3,14,5,8,1)
                  }[self.Nw]
        self.__piinv = [None]*len(self.__pi)
        for i,v in enumerate(self.__pi): self.__piinv[v]=i
        # set R_{d,j} constants:
        self.__R = {4: ((14,16),(52,57),(23,40),(5,37),
                        (25,33),(46,12),(58,22),(32,32)),
                    8: ((46,36,19,37),(33,27,14,42),
                        (17,49,36,39),(44,9,54,56),
                        (39,30,34,24),(13,50,10,17),
                        (25,29,39,43),(8,35,56,22)),
                   16: ((24,13,8,47,8,17,22,37),
                        (38,19,10,55,49,18,23,52),
                        (33,4,51,13,34,41,59,17),
                        (5,20,48,41,47,28,16,25),
                        (41,9,37,31,12,47,44,30),
                        (16,34,56,51,4,53,42,41),
                        (31,44,47,46,19,42,44,25),
                        (9,48,35,52,23,31,37,20))
                  }[self.Nw]
        # precompute key and tweak words lists:
        k = [self.K[i:i+64] for i in range(0,self.K.size,64)]
        C240 = Bits(0x1BD11BDAA9FC1A22,64)
        kNw = reduce(lambda x,y: x^y, k, C240)
        k.append(kNw)
        self.__k = k
        t = [self.T[0:64],self.T[64:128]]
        t.append(t[0]^t[1])
        self.__t = t

    @property
    def size(self):
        return self.K.size

    # compute the Nw subkeys of round s:
    def __ks(self,s):
        k,t = self.__k,self.__t
        ks=[]
        p = self.Nw+1
        for i in range(0,self.Nw-3):
            ks.append(k[(s+i)%p])
        ks.append(k[(s+self.Nw-3)%p]+t[s%3])
        ks.append(k[(s+self.Nw-2)%p]+t[(s+1)%3])
        ks.append(k[(s+self.Nw-1)%p]+s)
        return ks

    def __MIX(self,x0,x1,d,j):
        y0 = x0+x1
        y1 = rol(x1,self.__R[d%8][j])^y0
        return [y0,y1]

    def __MIXinv(self,y0,y1,d,j):
        rr = y0^y1
        x1 = ror(rr,self.__R[d%8][j])
        return [y0-x1,x1]

    def enc(self,M):
        if isinstance(M,bytes): M=Bits(M,bitorder=1)
        assert M.size==self.K.size
        v = [M[i:i+64] for i in range(0,M.size,64)]
        for d in range(self.Nr):
            if d%4==0:
                kd = self.__ks(d//4)
                e = [ (v[i]+kd[i]) for i in range(self.Nw) ]
            else:
                e = v
            f = []
            for j in range(0,self.Nw,2):
                f.extend(self.__MIX(e[j],e[j+1],d,j//2))
            for i in range(self.Nw):
                v[i] = f[self.__pi[i]]
        k = self.__ks(self.Nr//4)
        c = [(v[i]+k[i]) for i in range(self.Nw)]
        return b''.join([pack(x) for x in c])

    def dec(self,C):
        if isinstance(C,bytes): C=Bits(C,bitorder=1)
        assert C.size==self.K.size
        c = [C[i:i+64] for i in range(0,C.size,64)]
        k = self.__ks(self.Nr//4)
        v = [(c[i]-k[i]) for i in range(self.Nw)]
        for d in reversed(range(self.Nr)):
            f = [ v[self.__piinv[i]] for i in range(self.Nw) ]
            e = []
            for j in range(0,self.Nw,2):
                e.extend(self.__MIXinv(f[j],f[j+1],d,j//2))
            if d%4==0:
                kd = self.__ks(d//4)
                v = [ (e[i]-kd[i]) for i in range(self.Nw) ]
            else:
                v = e
        return b''.join([pack(x) for x in v])
