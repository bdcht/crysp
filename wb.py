#!/usr/bin/env python

from des import *

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
    return rks

def naked_F1(rks,R):
    RE = E(R)
    fout = Bits(0,32)
    ri,ro = 0,0
    for n in range(8):
        nri,nro = ri+6,ro+4
        x = RE[ri:nri]
        fout[ro:nro] = rks[n][x.ival]
        ri,ro = nri,nro
    return P(fout)

def table_rKT(r,K):
    rks = table_rKS(r,K)
    rkt = []
    for n in range(8):
        rks.append([0]*64)

def naked1(KS,M):
    assert M.size==64
    blk = IP(M)
    L = blk[0:32]
    R = blk[32:64]
    for r in range(16):
        L = L^naked_F1(KS[r],R)
        L,R = R,L
    L,R = R,L
    C = Bits(0,64)
    C[0:32] = L
    C[32:64] = R
    return IPinv(C)

