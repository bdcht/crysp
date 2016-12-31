# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license

from crysp.threefish import Threefish
from crysp.bits import *
from crysp.mode import Chain

from io import BytesIO
from functools import reduce

class Skein(object):
    def __init__(self,Nb,No,
                 schema=b"SHA3",version=1,Yl=0,Yf=0,Ym=0,
                 key=None,
                 prs=None,
                 PK=None,
                 kdf=None,
                 nonce=None):
        # block length and output length:
        assert Nb in (256,512,1024)
        self.Nb = Nb//8
        self.No = No
        # Config string (256 bits)
        self.C = schema+pack(Bits(version,16)//Bits(0,16)//Bits(No,64))
        self.Yl = Yl
        self.Yf = Yf
        self.Ym = Ym
        self.C += newbytes([Yl,Yf,Ym])+b'\0'*13
        self.key = key
        self.prs = prs
        self.PK  = PK
        self.kdf = kdf
        self.non = nonce

    def _initstate(self):
        self.G = b'\0'*self.Nb
        if self.key!=None: self.update(self.key,'key')
        self.update(self.C,'cfg')
        if self.prs: self.update(self.prs,'prs')
        if self.PK : self.update(self.PK,'PK')
        if self.kdf: self.update(self.kdf,'kdf')
        if self.non: self.update(self.non,'non')
        return self.G

    def update(self,M,T='msg',bitlen=None):
        if not (self.Yl==self.Yf==self.Ym==0) and T=='msg':
            self._treehash(M,bitlen)
        else:
            self.G = UBI(Threefish,self.G,Tweak(Type=T))(M,bitlen)

    def output(self,G):
        lq,lr = divmod(self.No,8)
        if lr!=0: lq += 1
        O = []
        n = l = 0
        T = Tweak(Type='out')
        ubi = UBI(Threefish,G,T)
        while l<lq:
            o = ubi(pack(Bits(n,64)))
            l += len(o)
            O.append(o)
            n += 1
        if l>lq: O[-1]=O[-1][:(lq-l)]
        return b''.join(O)

    def _treehash(self,M,bitlen=None):
        assert self.Yl>=1
        assert self.Yf>=1
        assert self.Ym>=2
        Nl = self.Nb<<self.Yl
        Nn = self.Nb<<self.Yf
        # leaf level (0):
        Mi = []
        Ts = Tweak(TreeLevel=1,Type='msg')
        for i in range(0,len(M),Nl):
            m = M[i:i+Nl]
            Mi.append(UBI(Threefish,self.G,Ts)(m))
            # spec for treehash is different from update
            # where Position evolves prior to UBI call...
            Ts.Position += Nl
        M = b''.join(Mi)
        # (tree) re-hashing previous level:
        while len(M)>self.Nb:
            # new node level:
            Ts.TreeLevel+=1
            Ts.Position=0  # ??? strange spec...
            if Ts.TreeLevel==self.Ym:
                self.G = UBI(Threefish,self.G,Ts)(M)
                return
            Mi = []
            for i in range(0,len(M),Nn):
                m = M[i:i+Nn]
                Mi.append(UBI(Threefish,self.G,Ts)(m))
                Ts.Position += Nn
            M = b''.join(Mi)
        if len(M)==self.Nb:
            self.G = M
            return
        # should not happen...
        raise ValueError


    def __call__(self,M,bitlen=None):
        self._initstate()
        self.update(M,'msg',bitlen)
        return self.output(self.G)


# -----------------------------------------------------------------------------
# Unique Block Iteration chain
class UBI(Chain):
    def __init__(self,cipherclass,G,Ts):
        Chain.__init__(self,cipherclass)
        self.G = G
        Ts = Tweak(Bits(Ts,bitorder=1))
        assert Ts.BitPad==0
        assert Ts.First==0
        assert Ts.Final==0
        self.Ts = Ts

    def __call__(self,M,bitlen=None):
        assert self.Ts.Position+len(M) < (1<<96)
        H = self.G
        for T,m in self.iterblocks(M,bitlen=bitlen):
            X = self._cipherclass(H,T).enc(m)
            H = self.xorstr(X,m)
        return H

    def iterblocks(self,M,bitlen=None):
        # pad M into M' (see spec, p.12-13)
        if bitlen is None:
            bitlen=len(M)*8
        else:
            M = (Bits(M,bitlen)//Bits(1,1)).bytes()
        # get BitPad flag:
        B = 1 if bitlen%8 else 0
        # pad M' into M'':
        l = len(M)
        lb = len(self.G)
        nb,rb = divmod(l,lb)
        lp=0
        if l==0 or rb>0:
            lp = lb-rb
            M += b'\0'*lp
            nb += 1
        # init generator:
        P = BytesIO(M)
        Ts = self.Ts
        Ts.First = 1
        for b in range(nb-1):
            m = P.read(lb)
            Ts.Position += lb
            yield (pack(Ts),m)
            Ts.First=0
        # last M'' block:
        Ts.Final = 1
        Ts.BitPad = B
        m = P.read(lb)
        Ts.Position += lb-lp
        yield (pack(Ts),m)

# -----------------------------------------------------------------------------
# Tweak bit string object allowing update of various fields:
class Tweak(Bits):

    def __init__(self,b=None,**kargs):
        if b is None:
            Bits.__init__(self,0,128)
            for k,v in iter(kargs.items()):
                if hasattr(self,k): setattr(self,k,v)
        else:
            Bits.__init__(self,b)

    @property
    def Position(self):
        return self[0:96].int()
    @Position.setter
    def Position(self,val):
        self[0:96] = val

    @property
    def reserved(self):
        return self[96:112].int()

    @property
    def TreeLevel(self):
        return self[112:119].int()
    @TreeLevel.setter
    def TreeLevel(self,val):
        self[112:119] = val

    @property
    def BitPad(self):
        return self[119:120].int()
    @BitPad.setter
    def BitPad(self,val):
        self[119:120] = val

    @property
    def Type(self):
        return self[120:126].int()
    @Type.setter
    def Type(self,val):
        self[120:126] = {'key':0,
                         'cfg':4,
                         'prs':8,
                         'PK' :12,
                         'kdf':16,
                         'non':20,
                         'msg':48,
                         'out':63}[val]

    @property
    def First(self):
        return self[126:127].int()
    @First.setter
    def First(self,val):
        self[126:127] = val

    @property
    def Final(self):
        return self[127:128].int()
    @Final.setter
    def Final(self,val):
        self[127:128] = val

# -----------------------------------------------------------------------------
