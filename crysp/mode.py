# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2013 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license

from crysp.padding import nopadding,pkcs7
from io import BytesIO
from crysp.bits import pack, unpack, Bits

# -----------------------------------------------------------------------------
# Mode of Operation Core class, default padding is nopadding.
class Mode(object):
    def __init__(self,cipher,pad=nopadding):
        self._cipher = cipher
        self.pad = pad(l=cipher.blocksize)

    @property
    def len(self):
        return self._cipher.blocksize//8

    def iterblocks(self,M,**kargs):
        for B in self.pad.iterblocks(M,**kargs):
            yield B

    # mandatory API:
    def enc(self,M):
        raise NotImplementedError
    def dec(self,C):
        raise NotImplementedError

    # xor input byte strings (over min length):
    def xorstr(self,a,b):
        a = bytes(a)
        b = bytes(b)
        return bytes([x^y for (x,y) in zip(a,b)])

# -----------------------------------------------------------------------------
# Electronic Code Book, default padding is pkcs7
class ECB(Mode):
    def __init__(self,cipher,pad=pkcs7):
        super().__init__(cipher,pad)
    # encryption mode
    def enc(self,M):
        C = []
        for b in self.iterblocks(M):
            C.append(self._cipher.enc(b))
        return b''.join(C)
    # decryption mode
    def dec(self,C):
        n,p = divmod(len(C),self.len)
        assert p==0
        P = BytesIO(C)
        M = []
        for b in range(n):
            M.append(self._cipher.dec(P.read(self.len)))
        return self.pad.remove(b''.join(M))

# -----------------------------------------------------------------------------
# Electronic Code Book with Cypher Text Stealing (nopadding)
class CTS_ECB(Mode):
    def __init__(self,cipher,pad=nopadding):
        super().__init__(cipher,pad)
    # encryption mode
    def enc(self,M):
        n,p = divmod(len(M),self.len)
        C = []
        for b in self.iterblocks(M[:n*self.len]):
            C.append(self._cipher.enc(b))
        if p>0:
            clast = C.pop()
            b = self.iterblocks(M[n*self.len:])[0]
            C.append(self._cipher.enc(b+clast[p:]))
            C.append(clast[0:p])
        return b''.join(C)
    # decryption mode
    def dec(self,C):
        n,p = divmod(len(C),self.len)
        P = BytesIO(C)
        M = []
        for b in range(n):
            M.append(self._cipher.dec(P.read(self.len)))
        if p>0:
            mlast = M.pop()
            M.append(self._cipher.dec(P.read(p)+mast[p:]))
            M.append(mlast[:p])
        return b''.join(M)

# -----------------------------------------------------------------------------
# Cipher Block Chaining, default padding is pkcs7
class CBC(Mode):
    def __init__(self,cipher,IV,pad=pkcs7):
        super().__init__(cipher,pad)
        assert len(IV)==self.len
        self.IV = IV
    # encryption mode
    def enc(self,M):
        C = [self.IV]
        for b in self.iterblocks(M):
            x = self.xorstr(b,C[-1])
            C.append(self._cipher.enc(x))
        return b''.join(C)
    # decryption mode
    def dec(self,C):
        l = self.len
        n,p = divmod(len(C),l)
        assert p==0
        M = []
        while len(C)>l:
            c = C[-l:]
            C = C[:-l]
            M.insert(0,self.xorstr(C[-l:],self._cipher.dec(c)))
        return self.pad.remove(b''.join(M))

# -----------------------------------------------------------------------------
# Cipher Block Chaining with Cipher Text Stealing (nopadding)
class CTS_CBC(Mode):
    def __init__(self,cipher,IV,pad=nopadding):
        super().__init__(cipher,pad)
        assert len(IV)==self.len
        self.IV = IV
    # encryption mode
    def enc(self,M):
        n,p = divmod(len(M),self.len)
        C = [self.IV]
        for b in self.iterblocks(M[:n*self.len]):
            x = self.xorstr(b,C[-1])
            C.append(self._cipher.enc(x))
        if p>0:
            clast = C.pop()
            b = self.iterblocks(M[n*self.len:]).ljust(self.len,b'\0')
            x = self.xorstr(b,clast)
            C.append(self._cipher.enc(x))
            C.append(clast[:p])
        return b''.join(C)
    # decryption mode
    def dec(self,C):
        l = self.len
        n,p = divmod(len(C),l)
        M = []
        if p>0:
            clast = C[-p:]
            C = C[:-p]
            cend = C[-l:]
            C = C[:-l]
            mend = self._cipher.dec(cend)
            mprev = self._cipher.dec(clast+mend[p:])
            M.insert(0,self.xorstr(clast,mend[:p]))
            M.insert(0,self.xorstr(C[-l:],mprev))
        C = self.IV+C
        while len(C)>l:
            c = C[-l:]
            C = C[:-l]
            M.insert(0,self.xorstr(C[-l:],self._cipher.dec(c)))
        return b''.join(M)

# -----------------------------------------------------------------------------
# Counter mode with provided iterable counter (no padding)
class DefaultCounter:
    def __init__(self,bytesize,iv=None):
        self.bytesize = bytesize
        if iv is not None:
            x = bytesize//2
            assert len(iv)==bytesize
            self.setup(iv[0:x],iv[x:])

    def setup(self,nonce=None,count=None):
        l = self.bytesize
        if nonce is None:
            nonce = b'\0'*(l//2)
        if count is None:
            count = b'\0'*(l//2)
        self.nonce = nonce
        self.count0 = count
        return self

    def reset(self):
        self.count = Bits(*unpack(self.count0,'>L'))

    def __call__(self):
        try:
            res = pack(self.count,'>L')
            self.count += 1
            return self.nonce+res
        except AttributeError:
            print("setup and reset counter is needed")

class CTR(Mode):
    def __init__(self,cipher,counter=None):
        super().__init__(cipher)
        if counter is None:
            counter = DefaultCounter(self.len)
        elif isinstance(counter,bytes):
            counter = DefaultCounter(self.len,counter)
        self.counter = counter

    # encryption mode
    def enc(self,M):
        self.counter.reset()
        self.pad.reset()
        C = []
        for b in self.iterblocks(M):
            c = self.counter()
            k = self._cipher.enc(c)
            x = self.xorstr(b,k)
            C.append(x)
        return b''.join(C)

    # decryption mode
    def dec(self,C):
        self.counter.reset()
        self.pad.reset()
        P = self.enc(C)
        n,p = divmod(len(C),self.len)
        if p>0:
            assert len(P)==n+1
            res = P[:-p]
        else:
            assert len(P)==n
            res = P
        return res

# -----------------------------------------------------------------------------
# Chain mode of Operation Core class for Digest algorithms, nopadding default
class Chain(object):
    def __init__(self,cipherclass,pad=nopadding):
        self._cipherclass = cipherclass
        self.pad = pad

    def iterblocks(self,M,**kargs):
        for b in self.pad.iterblocks(M,**kargs):
            yield b

    # mandatory API:
    def __call__(self,M):
        raise NotImplementedError

    # xor input byte strings (over min length):
    def xorstr(self,a,b):
        a = bytes(a)
        b = bytes(b)
        return bytes([x^y for (x,y) in zip(a,b)])

