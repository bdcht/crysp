# This code is part of crysp
# Copyright (C) 2011 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license

from .des import *
from .poly import Poly

# -----------------------------------------------------------------------------
# The bare naked DES (lacks de-linearization and encoding ! => M2 is sparse).
# The main weakness here is that the internal state of the whitebox holds
# a quite simple permutation of the DES internal (L,R) state after every round.
# This means that reducing rounds to N in the whitebox, leads to a N-round DES.
# The most obvious way of breaking it is to patch WT.enc for doing 1 round only
# and compute L1,R1 = IP(WT.enc(m)) ;)
class WhiteDES(object):

    def __init__(self,KT,tM1,tM2,tM3):
        self.KT = KT
        self.tM1 = tM1
        self.tM2 = tM2
        self.tM3 = tM3
        self.size = 64

    def __FX(self,v):
        res = Bits(0,96)
        for b in range(96):
            res[b] = (v&self.tM2[b]).hw()%2
        return res

    def enc(self,M):
        assert len(M)==8
        M = Bits(M)
        blk = M[self.tM1]
        for r in range(16):
            t = 0
            for n in range(12):
                nt = t+8
                blk[t:nt] = self.KT[r][n][blk[t:nt]]
                t = nt
            blk = self.__FX(blk)
        return (blk[self.tM3]).bytes()

    def dec(self,C):
        assert len(C)==8
        C = Bits(C)
        raise NotImplementedError

# -----------------------------------------------------------------------------
# precompute Sbox(.,K)

def table_rKS(r,K):
    fk = subkey(PC1(K),r)
    nfk = fk.split(6)
    rks = []
    for n in range(8):
        rks.append([0]*64)
    for v in range(64):
        re = Bits(v,6)
        for n in range(8):
            x = re^nfk[n]
            i = x[(5,0)].ival
            j = x[(4,3,2,1)].ival
            rks[n][re] = Bits(S(n,(i<<4)+j),4)[::-1].ival
    for n in range(8):
        rks[n] = tuple(rks[n])
    return tuple(rks)


def table_rKT(r,K):
    rks = table_rKS(r,K)
    rkt = []
    for n in range(12):
        rkt.append(list(range(256)))
    for v in range(256):
        re = Bits(v,8)
        for n in range(8):
            x = Bits(rks[n][re[0:6].ival],4)//re[(0,5,6,7)]
            rkt[n][re.ival] = x.ival
    for n in range(12):
        rkt[n] = tuple(rkt[n])
    return rks,tuple(rkt)

def getrbits_T_in():
    r = E(Poly(list(range(32)))).ival
    sr = set(list(range(32)))
    rbits=[]
    for i in range(8):
        sr.remove(r[0])
        sr.remove(r[5])
        rbits += [r[0],r[5]]
        r = r[6:]
    return rbits+list(sr)

def table_M1():
    l,r = range(32),Poly(list(range(32,64)))
    re = E(r).ival
    rbits = r.ival
    blk = []
    for b in range(12):
        blk.append([0]*8)
        if b<8:
            blk[b][0:6]=re[0:6]
            rbits.remove(re[0])
            rbits.remove(re[5])
            re = re[6:]
            blk[b][6:8]=l[0:2]
            l = l[2:]
        else:
            blk[b][0:4]=l[0:4]
            blk[b][4:8]=rbits[0:4]
            l = l[4:]
            rbits = rbits[4:]
    assert len(rbits)==0
    assert len(l)==0
    table = []
    for b in range(12):
        table.extend(blk[b])
    M = Poly(list(range(64)))
    return IP(M)[table].ival

def SRLRformat():
    I = Poly(list(range(96)))
    SR = Poly([0]*32)
    L = Poly([0]*32)
    R = Poly([0]*32)
    rbits = getrbits_T_in()
    for i in range(0,8):
        s = I[8*i:8*i+8].ival
        SR[4*i:4*i+4]= s[:4]
        R[rbits[:2]] = s[4:6]
        L[2*i:2*i+2] = s[6:8]
        rbits = rbits[2:]
    for i in range(8,12):
        s = I[8*i:8*i+8].ival
        L[4*i-16:4*i-12] = s[:4]
        R[rbits[:4]] = s[4:]
        rbits = rbits[4:]
    return SR,L,R

def ERLRformat():
    I = Poly(list(range(96)))
    ER = Poly([0]*48)
    L = Poly([0]*32)
    R = Poly([0]*32)
    rbits = getrbits_T_in()
    for i in range(0,8):
        s = I[8*i:8*i+8].ival
        ER[6*i:6*i+6]= s[:6]
        R[rbits[:2]] = [s[0],s[5]]
        L[2*i:2*i+2] = s[6:8]
        rbits = rbits[2:]
    for i in range(8,12):
        s = I[8*i:8*i+8].ival
        L[4*i-16:4*i-12] = s[:4]
        R[rbits[:4]] = s[4:]
        rbits = rbits[4:]
    return ER,L,R

def table_M2():
    Mat = [Bits(0,96) for i in range(96)]
    SR,L,R = SRLRformat()
    newL = R.ival
    newR = list(zip(P(SR),L))
    RE = [newR[i] for i in E(Poly(list(range(len(L)))))]
    m=[]
    for r in range(8):
        m += RE[0:6]+newL[0:2]
        RE = RE[6:]
        newL  = newL[2:]
    rbits = getrbits_T_in()[16:]
    for r in range(4):
        m += newL[0:4]
        for b in rbits[:4]:
            m += [newR[b]]
        newL = newL[4:]
        rbits = rbits[4:]
    assert len(m)==96
    for v in range(96):
        l = m[v]
        try:
            for x in l: Mat[v][x]=1
        except TypeError:
            Mat[v][l]=1
        Mat[v] = Mat[v].ival
    return Mat,m

def table_M3():
    ER,L,R = ERLRformat()
    C = Poly(R.ival+L.ival)
    return IPinv(C).ival

