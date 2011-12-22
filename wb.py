#!/usr/bin/env python

import pickle
import random
from des import *

# -----------------------------------------------------------------------------
# Electronic Code Book mode of Operation
class ECB(object):

# encryption mode
    def enc(self,M):
        n,p = divmod(len(M),8)
        if p>0:
            M += chr(8-p)*(8-p)
            n += 1
            print "warning: padding added %d byte(s) %x"%(8-p,8-p)
        C = []
        for b in range(n):
            C.append(hex(self._cipher(Bits(M[0:8]),1)))
            M = M[8:]
        assert len(M)==0
        return ''.join(C)

# decryption mode
    def dec(self,C):
        n,p = divmod(len(C),8)
        assert p==0
        M = []
        for b in range(n):
            M.append(hex(self._cipher(Bits(C[0:8]),-1)))
            C = C[8:]
        assert len(C)==0
        return ''.join(M)

# null cipher
    def _cipher(self,B,direction):
        return B

# -----------------------------------------------------------------------------
# The easy WhiteBox DES:

def table_rKS(r,K):
    fk = subkey(PC1(K),r)
    nfk = [fk[6*n:6*n+6] for n in range(8)]
    rks = []
    for n in range(8):
        rks.append([0]*64)
    for v in range(64):
        re = Bits(v,6)
        for n in range(8):
            x = re^nfk[n]
            i = x[(5,0)].ival
            j = x[(4,3,2,1)].ival
            rks[n][re.ival] = Bits(S(n,(i<<4)+j),4)[::-1].ival
    for n in range(8):
        rks[n] = tuple(rks[n])
    return tuple(rks)


class WhiteBoxDes(ECB):

    def __init__(self,KS):
        self.KS = KS

    def _cipher(self,M,d):
        assert M.size==64
        blk = IP(M)
        L = blk[0:32]
        R = blk[32:64]
        for r in range(16)[::d]:
            L = L^self.F(r,R)
            L,R = R,L
        L,R = R,L
        C = Bits(0,64)
        C[0:32] = L
        C[32:64] = R
        return IPinv(C)

    def F(self,r,R):
        RE = E(R)
        fout = Bits(0,32)
        ri,ro = 0,0
        for n in range(8):
            nri,nro = ri+6,ro+4
            x = RE[ri:nri]
            fout[ro:nro] = self.KS[r][n][x.ival]
            ri,ro = nri,nro
        return P(fout)

# -----------------------------------------------------------------------------
# The naked (almost easy) WhiteBox DES:

def table_rKT(r,K):
    rks = table_rKS(r,K)
    rkt = []
    for n in range(8):
        rkt.append([0]*256)
    for v in range(256):
        e = Bits(v,8)
        for n in range(8):
            rkt[n][e.ival] = (Bits(rks[n][e[0:6].ival],4)//e[(0,5,6,7)]).ival
    for n in range(8):
        rkt[n] = tuple(rkt[n])
    return tuple(rkt)


class NakedDes(ECB):

    def __init__(self,KT):
        self.KT = KT

    def _cipher(self,M,d):
        assert M.size==64
        blk = IP(M)
        L = blk[0:32]
        R = blk[32:64]
        for r in range(16)[::d]:
            L = L^self.F(r,R)
            L,R = R,L
        L,R = R,L
        C = Bits(0,64)
        C[0:32] = L
        C[32:64] = R
        return IPinv(C)

