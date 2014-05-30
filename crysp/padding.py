# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license

from crysp.bits import *

class PaddingError(Exception):
    def __init__(self,value):
        self.value = value

#------------------------------------------------------------------------------
class nopadding(object):
    def __init__(self,*args,**kargs):
        pass
    def lastblock(self,m,**kargs):
        return m
    def remove(self,m):
        return m

#------------------------------------------------------------------------------
# RFC1321 step 3.1.
# This padding scheme is defined by ISO/IEC 9797-1 as Padding Method 2.
class bitpadding(object):
    # init padding for blocks of l bytes
    def __init__(self,l):
        self.len = l
    # return padded last block.
    # optional kargs are:
    # - bitlen: number of input bit in m.
    def lastblock(self,m,**kargs):
        bitlen = kargs.get('bitlen',None)
        if bitlen is None:
            bitlen = len(m)*8
        assert bitlen<(self.len*8)
        b = hex(Bits(m,bitlen)//Bits(1,self.len*8-bitlen))
        assert len(b)==self.len
        return b
    # remove padding:
    def remove(self,m):
        b=Bits(m[-self.len:])
        b.size=str(b).rfind('1')
        return m[:-self.len]+hex(b)

#------------------------------------------------------------------------------
class pkcs7(object):
    # init padding for blocks of l bytes
    def __init__(self,l):
        self.len = l
    # return padded last block.
    # (no optional kargs)
    def lastblock(self,m,**kargs):
        p = len(m)
        assert p<self.len
        return m+(chr(self.len-p)*(self.len-p))
    # remove padding:
    def remove(self,c):
        n = ord(c[-1])
        if n>self.len or (c[-n:]!=c[-1]*n):
            raise PaddingError(c)
        else:
            return c[:-n]

#------------------------------------------------------------------------------
class X923(object):
    # init padding for blocks of l bytes
    def __init__(self,l):
        self.len = l
    # return padded last block.
    # (no optional kargs)
    def lastblock(self,m,**kargs):
        p = len(m)
        assert p<self.len
        r = m+('\0'*(self.len-p))
        r[-1] = chr(self.len-p)
    # remove padding:
    def remove(self,c):
        n = ord(c[-1])
        if n>self.len or (c[-n:-1]!='\0'*(n-1)):
            raise PaddingError(c)
        else:
            return c[:-n]



