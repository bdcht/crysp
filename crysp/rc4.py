# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2005 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.poly import *
from crysp.utils.operators import *


class RC4(object):

    def __init__(self,K):
        self.K = Poly(K)
        keylen = self.K.dim
        assert keylen>0
        assert keylen<=256
        self.ksa()

    def ksa(self):
        S = Poly(list(range(256)),8)
        j=0
        for i in range(256):
            j = (j+S.ival[i]+self.K.ival[i%self.K.dim])&0xff
            S[i,j] = S[j,i]
        self.S = S

    def keystream(self,l):
        S = self.S
        ks = []
        i,j = 0,0
        while len(ks)<l:
            i = (i+1)&0xff
            j = (j+S.ival[i])&0xff
            S[i,j] = S[j,i]
            ks.append(S.ival[(S.ival[i]+S.ival[j])&0xff])
        return Poly(ks,8)

    def enc(self,m):
        return pack(Poly(m)^self.keystream(len(m)))

    def dec(self,c):
        return self.enc(c)
