# This code is part of crysp
# Copyright (C) 2006-2014 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

import struct
import codecs

__all__ = ['struct','Bits','reverse_byte','pack','unpack']

def reverse_byte(b):
    "reverse all bits in a byte-size int"
    return (b * 0x0202020202 & 0x010884422010) % 1023

def pack(obj,fmt='<L'):
    """write obj in little-endian format by default (<L).
       use '>L' for big-endian format.
    """
    assert fmt in ['<L','>L']
    s = [x.ival&0xff for x in obj.split(8)]
    if fmt=='>L': s.reverse()
    return bytes(s)

def unpack(istr,bigend=False):
    """generalize struct.unpack to return one int value of arbitrary bit length.
    """
    r = len(istr)
    size = r<<3
    i = 0
    b = 0
    endian = '>' if bigend else '<'
    for q,f in [(8,'Q'),(4,'L'),(2,'H'),(1,'B')]:
        n,r = divmod(r,q)
        if n>0:
            c = n*q
            qlen = q<<3
            s,istr = istr[:c],istr[c:]
            for v in struct.unpack('%c%d%c'%(endian,n,f),s):
                b = b|(v<<i) if not bigend else (b<<i)|v
                i += qlen
        if r==0: return (b,size)
    raise ValueError

hextab_r = ('0000','1000','0100','1100',
            '0010','1010','0110','1110',
            '0001','1001','0101','1101',
            '0011','1011','0111','1111')

class Bits(object):
    """The Bits class represents an ordered sequence of bits.

       Attributes:

       ival: holds the bit sequence as a native python integer (bit0 is LSB).
       size: actual length of the sequence (ival might encode more bits)
       mask: automatically adjusted to size, but can be redefined if needed.

       Note:

       Bits can be represented as follows:

       - human-readable string of chars: str(Bits(b'\x80',5)) =>  '10000'
       - human-readable dot alternative: Bits(b'\x80',5).todots() =>  '|.    |'
       - the bit sequence as a list: Bits(b'\x80',5).bitlist() = [1,0,0,0,0]
       - integer: using internal ival field is not recommended, use Bits.int()
       - raw bitstream as bytes: Bits(b'\x82',5).bytes() => b'\x80'.
         (note that if size is not a multiple of 8, the bitstream is naturally
         extended with 0 bit padding). Again, bit0 is MSB of 1st byte.
       - raw little-endian "packed" bytes: the struct.pack extension
         to encode the sequence as a little-endian arbitrary long integer is
         provided by function :func:`pack`.
    """

    __slots__ = ['ival','__sz','mask']

    def __init__(self,v=None,size=None,bitorder=-1):
        """ 
        Bits instance can be initialized from:

        - int values: bits are ordered from LSB to MSB.
        - list (of 0 and 1s): bits are ordered as listed.
        - bytes: The bit ordering of the given sequence of bytes is chosen
                 by the bitorder parameter. See method :meth:`load`.
        """
        self.ival = self.__sz = self.mask = 0
        if v is not None:
            if isinstance(v,Bits):
                self.ival = v.ival
                self.__sz = v.size
                self.mask = v.mask
            elif isinstance(v,int):
                self.ival = abs(v*int(1))
                if self.ival>0 and (size is None):
                    self.size = self.ival.bit_length()
            elif isinstance(v,list):
                self.size = len(v)
                self.ival = 0
                for x in reversed(v):
                    self.ival = (self.ival<<1)|(x&1)
            elif isinstance(v,bytes):
                self.load(v,bitorder)
            else:
                raise TypeError(v)
            #adjust size (and mask):
            if size!=None: self.size = size

    def load(self,v,bitorder=-1):
        """load a sequence of bytes according to some bitorder convention. 

           Parameters:
              - v (bytes): input sequence. The sequence is decoded as a list
                           of big-endian integers of size given by the magnitude
                           of bitorder. The sequence length must be a multiple of
                           bitorder.
              - bitorder (int): bit ordering convention (defaults to -1).
                                If negative, bits are read from msb to lsb.
                                If positive, bits are read from lsb to msb.
                                The magnitude of bitorder controls the number of bits
                                from lsb to msb.
           
           Note:
                By default, bitorder=-1 which means that each byte is considered
                as an uint8 integer read from msb to lsb. This ordering corresponds
                to a *bitstream* mode.
                For example: Bits(b'\x80',5) is the sequence [1,0,0,0,0] and
                leads to ival=0x1, size=5, mask=0x1f.

                To consider bytes as the little-endian encoding of ival, use 
                the bitorder=+1 parameter. For example::
                Bits(b'\x01\x0f',size=13,bitorder=1) is loaded as
                [1,0,0,0,0,0,0,0,1,1,1,1,0], ival=0x0f01, size=13, mask=0x1fff.

                To consider bytes as the big-endian encoding of ival,
                change the magnitude of bitorder to the size of v:
                Bits(b'\x01\x0f',size=13,bitorder=2) is loaded as
                ival = 0x010f, size=13, mask=0x1fff.
                Alternatively, bitorder=0 is equivalent to setting bitorder=len(v).  

                This convention allows to load integers from mixed-endian encoding
                like uint32 value 0x0a0b0c0d can be loaded with:
                Bits(b'\x0b\x0a\x0d\x0c'[::-1],bitorder=2) (PDP-endian).
                Bits(b'\x0c\x0d\x0a\x0b',bitorder=2) (Honeywell316).
        """
        bytestr = bytes(v)
        l = len(bytestr)
        self.size = l*8
        if bitorder<0:
            f = reverse_byte
            bitorder = -bitorder
        elif bitorder>0:
            f = lambda x:x
        else:
            f = lambda x:x
            bitorder = l
        if l%bitorder != 0:
            raise ValueError("v length must be a multiple of bitorder.")
        v = 0
        elsz = bitorder*8
        for i in reversed(range(0,l,bitorder)):
            e = bytestr[i:i+bitorder]
            x = 0
            for b in e:
                x = (x<<8) | f(b)
            v = (v<<elsz) | x
        self.ival = v

    def __len__(self):
        "length in number of bits"
        return self.size

    def bit(self,i):
        "extract bit integer value (0 or 1) at index i."
        if 0 <= i < self.__sz:
            return (self.ival>>i)&0x1
        elif 0<= -i <= self.__sz:
            return (self.ival>>(self.__sz+i))&0x1
        else:
            raise IndexError

    def int(self,sign=1):
        """get the Python integer representation, optionally taking into account
           the given sign (defaults to 1: unsigned, use -1 for negatives).
        """
        if sign==-1 and self.bit(-1)==1:
            return -(self.ival^self.mask)-1
        return self.ival&self.mask

    def __int__(self):
        "same as obj.int(), implements natural conversion to unsigned int for self."
        return self.int()

    def __index__(self):
        "same as obj.int(), implements natural conversion to unsigned int for self."
        return self.int()

    @property
    def size(self):
        return self.__sz

    @size.setter
    def size(self,v):
        self.__sz = v
        self.mask = (1<<v)-1
        self.ival &= self.mask

    def __repr__(self):
        c = self.__class__
        l = self.__sz
        s = self.ival
        return '<%s instance with ival=%x (len=%d)>'%(c,s,l)

    def __str__(self):
        "get the *bitstream* represention as an unicode str of 0s and 1s."
        xval = ("%x"%(self.ival&self.mask)).zfill(self.__sz//4+1)
        s = [hextab_r[int(x,16)] for x in xval]
        s.reverse()
        return u''.join(s)[:self.__sz]

    def __bytes__(self):
        "get the *bitstream* representation as a bytes str."
        v = self.ival&self.mask
        i = 0
        s = []
        while i<self.__sz:
          s.append(reverse_byte(v&0xff))
          v = v>>8
          i += 8
        return bytes(s)

    def bytes(self):
        "get the *bitstream* representation as a bytes str."
        return self.__bytes__()

    def hex(self):
        "get the *bitstream* representation as an hex string."
        return codecs.encode(self.__bytes__(),'hex')

    def todots(self):
        "get the *bitstream* representation as a 1-dot 0-blank string."
        return u'|%s|'%str(self).replace('0',' ').replace('1','.')

    def split(self,subsize,bigend=False):
        """returns a list of Bits objects of size subsize, ordered from
           low bits to high bits if bigend is False (default) or from high bits
           to low bits if bigend=True.
        """
        l = []
        i = 0
        while i<self.__sz:
            l.append(self[i:i+subsize])
            i += subsize
        if bigend:
            l.reverse()
        return l

    def __cmp__(self,a):
        if not isinstance(a,Bits):
            raise AttributeError
        if self.size != a.size:
            raise ValueError
        return cmp(self.ival,a.ival)

    def __eq__(self,a):
        if isinstance(a,Bits): a=a.ival
        return (self.ival==a)

    def __ne__(self,a):
        if isinstance(a,Bits): a=a.ival
        return (self.ival!=a)

    def __neg__(self):
        return Bits((-self.ival) % self.mask, self.size)

    def __iter__(self):
        for x in range(self.size):
            yield self.bit(x)

    def __getitem__(self,i):
        """getitem operator defines b[i], b[i:j] and b[list] which returns the requested
           bit values as a Bits object of selected bits. If parameter i is a list, each
           value in the list extract one bit at index value.
        """
        if isinstance(i,int):
            return Bits(self.bit(i),1)
        elif isinstance(i,slice):
            start,stop,step = i.indices(self.__sz)
            if step==1 and stop>=start:
                v = (self.ival&((1<<stop)-1))>>start
                return Bits(v,stop-start)
            else:
                return self[range(self.__sz)[i]]
        else:
            v = 0
            for x in reversed(i):
                v = (v<<1)|((self.ival>>x)&1)
            return Bits(v,len(i))

    def __setitem__(self,i,v):
        """setitem operator defines b[i]=v, b[i:j]=v and b[list]=v which sets the
           requested bit values from the right-value v given as an int or list of 
           (0,1) ints.
        """
        if isinstance(i,int):
            assert v in (0,1)
            if   0<= i< self.__sz   : p=i
            elif 0<=-i<(self.__sz+1): p=self.__sz+i
            else: raise IndexError
            if v==0: self.ival &= (self.mask^((0x1)<<p))
            if v==1: self.ival |= (0x1)<<p
        else:
            v = Bits(v)
            if isinstance(i,slice):
              start,stop,step = i.indices(self.__sz)
              if step==1 and stop>start:
                  mask = self.mask^((1<<stop)-1)^((1<<start)-1)
                  self.ival = (self.ival&mask)|(v.ival<<start)
                  return
              r = range(start,stop,step)
            else:
                r = i
            assert len(r)==len(v)
            for j,b in zip(r,v):
                self[j] = b

    def __lshift__(self,i):
        res = Bits(self)
        res.ival = (res.ival<<i)&res.mask
        return res
    def __rshift__(self,i):
        res = Bits(self)
        res.ival = (res.ival>>i)&res.mask
        return res
    def __invert__(self):
        res = Bits(self)
        res.ival = res.ival ^ res.mask
        return res

    def zeroextend(self,size):
        "extend to size filling with bit 0."
        if size>self.size:
            self.size = size
        return self

    def signextend(self,size):
        "extend to size filling with bit self[-1] (ie. msb)."
        if size>self.size:
            m = self.mask
            s = self[-1]
            self.size = size
            if s==1:
                m ^= self.mask
                self.ival |= m
        return self

    def extend(self,sign,size):
        "zeroextend or signextend depending on the sign boolean parameter."
        return self.signextend(size) if sign is True else self.zeroextend(size)

    def __and__(self,rvalue):
      if not isinstance(rvalue,Bits):
        obj = Bits(rvalue)
      else:
        obj = rvalue
      if self.size > obj.size:
        res = Bits(self)
      else:
        res = Bits(obj)
      res.ival = ( self.ival & obj.ival )
      return res

    def __or__(self,rvalue):
        if not isinstance(rvalue,Bits):
            obj = Bits(rvalue)
        else:
            obj = rvalue
        if self.size > obj.size:
            res = Bits(self)
        else:
            res = Bits(obj)
        res.ival = ( self.ival | obj.ival )
        return res

    def __xor__(self,rvalue):
        if not isinstance(rvalue,Bits):
            obj = Bits(rvalue)
        else:
            obj = rvalue
        if self.size > obj.size:
            res = Bits(self)
        else:
            res = Bits(obj)
        res.ival = ( self.ival ^ obj.ival )
        return res

    def __add__(self,rvalue):
        if not isinstance(rvalue,Bits):
            obj = Bits(rvalue)
        else:
            obj = rvalue
        if self.size > obj.size:
            res = Bits(self)
        else:
            res = Bits(obj)
        res.ival = ( self.ival + obj.ival )&res.mask
        return res

    def __sub__(self,rvalue):
        if not isinstance(rvalue,Bits):
            obj = Bits(rvalue)
        else:
            obj = rvalue
        if self.size > obj.size:
            res = Bits(self)
        else:
            res = Bits(obj)
        res.ival = ( self.ival - obj.ival )&res.mask
        return res

    def __mul__(self,rvalue):
        if isinstance(rvalue,Bits):
            m = rvalue.ival
        res = self.ival*m
        return Bits(res,self.size)

    def __rand__(self,lvalue):
        return (self & lvalue)
    def __ror__(self,lvalue):
        return (self | lvalue)
    def __rxor__(self,lvalue):
        return (self ^ lvalue)
    def __radd__(self,lvalue):
        return (self + lvalue)
    def __rsub__(self,lvalue):
        return Bits(lvalue,self.size)-self

#   operator // is used for concatenation:
    def __floordiv__(self,rvalue):
        if not isinstance(rvalue,Bits):
          obj = Bits(rvalue)
        else:
          obj = rvalue
        size = self.size+obj.size
        return Bits(self.ival | obj.ival<<self.size, size)

    def bitlist(self,dir=1):
        """returns the python list of bits as 0/1 ints ordered from lsb to msb if
           dir is 1, or ordered from msb to lsb if dir==-1.
        """
        l = list(self)
        if dir==-1: l.reverse()
        return l

    def hw(self):
        "returns the hamming weight of the object (count of 1s)."
        return self.bitlist().count(1)

    def hd(self,other):
        "returns the hamming distance to other object of same length."
        if not isinstance(other,Bits):
            obj = Bits(other)
        else:
            obj = other
        if self.size != obj.size:
            raise ValueError
        return (self^obj).hw()

