# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *
import StringIO

class PaddingError(Exception):
    def __init__(self,value):
        self.value = value

class blockiterator(object):
    def __init__(self,l):
        self.blocksize = l
        n,r = divmod(l,8)
        if r!=0: raise PaddingError('invalid block size')
        self.blocklen = n
        self.padflag = False
        self.bitcnt = 0
    def iterblocks(self,m,**kargs):
        padding = kargs.get('padding',True)
        if self.padflag: padding=False
        bitlen = kargs.get('bitlen',None)
        mlen = len(m)*8
        if bitlen is None:
            bitlen = mlen
        assert bitlen<=mlen
        if padding is False and bitlen%self.blocksize>0:
            raise PaddingError('input not a multiple of block size')
        P = StringIO.StringIO(m)
        Pi = P.read(self.blocklen)
        while len(Pi)==self.blocklen:
            nc = self.bitcnt + self.blocksize
            if nc<bitlen:
                self.bitcnt = nc
                yield Pi
                Pi = P.read(self.blocklen)
            else:
                break
        if padding:
            nPi = self.lastblock(Pi,**kargs)
            b,lastb= nPi[:self.blocklen],nPi[self.blocklen:]
            yield b
            if len(lastb)>0:
                self.bitcnt = 0
                yield lastb
        else:
            assert len(Pi)==self.blocklen
            self.bitcnt += self.blocksize
            yield Pi
        P.close()

#------------------------------------------------------------------------------
class nopadding(blockiterator):
    def lastblock(self,m,**kargs):
        self.padflag = True
        self.bitcnt += len(m)*8
        return m
    def remove(self,m):
        return m

#------------------------------------------------------------------------------
class Nullpadding(blockiterator):
    def lastblock(self,m,**kargs):
        bitlen = kargs.get('bitlen',None)
        if bitlen is None:
            bitlen = len(m)*8
        else:
            bitlen = bitlen-self.bitcnt
        q = self.blocksize-bitlen
        b = hex(Bits(m,bitlen)//Bits(0,q))
        assert len(b)==self.blocklen
        self.bitcnt += bitlen
        self.padflag = True
        self.padcnt = q
        return b
    # remove padding:
    def remove(self,m):
        b=Bits(m[-self.blocklen:])
        b.size -= self.padcnt
        return m[:-self.blocklen]+hex(b)

#------------------------------------------------------------------------------
# RFC1321 step 3.1.
# This padding scheme is defined by ISO/IEC 9797-1 as Padding Method 2.
class bitpadding(blockiterator):
    # return padded last block.
    # optional kargs are:
    # - bitlen: number of input bit in m.
    def lastblock(self,m,**kargs):
        bitlen = kargs.get('bitlen',None)
        if bitlen is None:
            bitlen = len(m)*8
        else:
            bitlen = bitlen-self.bitcnt
        q = (self.blocksize-bitlen) or self.blocksize
        b = hex(Bits(m,bitlen)//Bits(1,q))
        self.bitcnt += bitlen
        self.padflag = True
        self.padcnt  = q
        return b
    # remove padding:
    def remove(self,m):
        b=Bits(m[-self.blocklen:])
        b.size=str(b).rfind('1')
        return m[:-self.blocklen]+hex(b)

#------------------------------------------------------------------------------
class pkcs7(blockiterator):
    # return padded last block.
    # (no optional kargs)
    def lastblock(self,m,**kargs):
        p = len(m)
        self.padflag = True
        self.bitcnt += p*8
        q = (self.blocklen-p) or self.blocklen
        if q==0: q=self.blocklen
        self.padcnt = q*8
        return m+(chr(q)*q)
    # remove padding:
    def remove(self,c):
        q = ord(c[-1])
        if n>self.blocklen or (c[-q:]!=c[-1]*q):
            raise PaddingError(c)
        else:
            return c[:-q]

#------------------------------------------------------------------------------
class X923(blockiterator):
    # return padded last block.
    # (no optional kargs)
    def lastblock(self,m,**kargs):
        assert self.blocklen<256
        p = len(m)
        q = (self.blocklen-p) or self.blocklen
        r = m+('\0'*(q-1))
        r += chr(q)
        self.padflag = True
        self.bitcnt += p*8
        self.padcnt  = q*8
        return r
    # remove padding:
    def remove(self,c):
        q = ord(c[-1])
        if n>self.blocklen or (c[-q:-1]!='\0'*(q-1)):
            raise PaddingError(c)
        else:
            return c[:-q]

#------------------------------------------------------------------------------
class MDpadding(blockiterator):
    def __init__(self,l,wsize):
        self.wsize = wsize
        super(MDpadding,self).__init__(l)
    # add sha1 padding:
    def lastblock(self,m,**kargs):
        bitlen = kargs.get('bitlen',None)
        if bitlen is None:
            bitlen = self.bitcnt+len(m)*8
        assert self.bitcnt<=bitlen
        needed = bitlen-self.bitcnt
        mb = Bits(m,size=needed)
        countersize = self.wsize*2
        N = self.blocksize-1-countersize-needed
        if N<0: N += self.blocksize
        pad = mb//Bits(1,1)//Bits(0,N)
        self.padflag = True
        self.bitcnt += needed
        return hex(pad)+pack(Bits(bitlen,countersize))
    # remove sha1 padding:
    def remove(self,c):
        clen = self.wsize/4
        counter,_ = unpack(c[-clen:])
        c = list(c[:-clen])
        while Bits(c[-1]).ival==0:
            c.pop()
        if len(c)==0: raise PaddingError("failed to remove padding")
        b = Bits(c.pop())
        b.size=str(b).rfind('1')
        return ''.join(c)+hex(b)

#------------------------------------------------------------------------------
class SHApadding(blockiterator):
    def __init__(self,l,wsize):
        self.wsize = wsize
        super(SHApadding,self).__init__(l)
    # add sha padding:
    def lastblock(self,m,**kargs):
        bitlen = kargs.get('bitlen',None)
        if bitlen is None:
            bitlen = self.bitcnt+len(m)*8
        assert self.bitcnt<=bitlen
        needed = bitlen-self.bitcnt
        mb = Bits(m,size=needed)
        countersize = self.wsize*2
        N = self.blocksize-1-countersize-needed
        if N<0: N += self.blocksize
        pad = mb//Bits(1,1)//Bits(0,N)
        self.padflag = True
        self.bitcnt += needed
        return hex(pad)+pack(Bits(bitlen,countersize),'>L')
    # remove sha padding:
    def remove(self,c):
        clen = self.wsize/4
        counter,_ = unpack(c[-clen:],bigend=True)
        c = list(c[:-clen])
        while Bits(c[-1]).ival==0:
            c.pop()
        if len(c)==0: raise PaddingError("failed to remove padding")
        b = Bits(c.pop())
        b.size=str(b).rfind('1')
        return ''.join(c)+hex(b)

#------------------------------------------------------------------------------
class Blakepadding(blockiterator):
    def __init__(self,size):
        self.hsize = size
        self.wsize = 64 if size>256 else 32
        l = 1024 if size>256 else 512
        super(Blakepadding,self).__init__(l)
    # add sha1 padding:
    def lastblock(self,m,**kargs):
        bitlen = kargs.get('bitlen',None)
        if bitlen is None:
            bitlen = self.bitcnt+len(m)*8
        assert self.bitcnt<=bitlen
        needed = bitlen-self.bitcnt
        mb = Bits(m,size=needed)
        countersize = self.wsize*2
        N = self.blocksize-2-countersize-needed
        if N<0: N += self.blocksize
        v = 1 if self.hsize in (256,512) else 0
        pad = mb//Bits(1,1)//Bits(0,N)//Bits(v,1)
        self.padflag = True
        self.bitcnt += needed
        return hex(pad)+pack(Bits(bitlen,countersize),'>L')
    # remove sha1 padding:
    def remove(self,c):
        clen = self.wsize/4
        counter,_ = unpack(c[-clen:],bigend=True)
        c = list(c[:-clen])
        b = Bits(c.pop())
        if self.hsize in (256,512):
            assert b[7]==1
            b[7]=0
        if b.ival!=0: c.append(hex(b))
        while Bits(c[-1]).ival==0:
            c.pop()
        if len(c)==0: raise PaddingError("failed to remove padding")
        b = Bits(c.pop())
        b.size=str(b).rfind('1')
        return ''.join(c)+hex(b)

#------------------------------------------------------------------------------
