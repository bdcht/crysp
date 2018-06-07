# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2017 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *

class HMAC(object):
    def __init__(self,h,k=None):
        self.h = h
        if k!=None: self.setkey(k)

    def setkey(self,k):
        sz = self.h.blocksize//8
        if   len(k)>sz: k = self.h(k)
        elif len(k)<sz: k +=b'\0'*(sz-len(k))
        self.K = newbytes(k)

    def __call__(self,m):
        assert self.K
        a = self.K
        b = newbytes(b'\x5c'*(self.h.blocksize//8))
        opad = newbytes([x^y for (x,y) in zip(a,b)])
        b = newbytes(b'\x36'*(self.h.blocksize//8))
        ipad = newbytes([x^y for (x,y) in zip(a,b)])
        h1 = self.h(ipad+newbytes(m))
        return self.h(opad+h1)
