# This code is part of crysp
# Copyright (C) 2006-2014 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

import struct
import codecs
from builtins import bytes as newbytes

try:
    IntType = (int,long)
except NameError:
    IntType = (int,)

# reverse all bits in a byte:
def reverse_byte(b):
    return (b * 0x0202020202 & 0x010884422010) % 1023

# write obj in little-endian format by default (<L).
# use '>L' for big-endian format.
def pack(obj,fmt='<L'):
    assert fmt in ['<L','>L']
    s = [x.ival&0xff for x in obj.split(8)]
    if fmt=='>L': s.reverse()
    return newbytes(s)

# generalize struct.unpack to return one int value of
# arbitrary bit length.
def unpack(istr,bigend=False):
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

# The Bits class represents an ordered sequence of bits.
#
# ival: holds the bit sequence as a native python integer (bit0 is LSB).
# size: actual length of the sequence (ival might encode more bits)
# mask: automatically adjusted to size, but can be redefined if needed.
#
# Bits instance can be initialised from:
#  - int values: bits are ordered from LSB to MSB.
#  - list (of bits) : bits are ordered as listed.
#  - strings        : by default, bit0 is MSB of 1st byte! (stream mode)
#                     This means that Bits('\x80',5) is the sequence
#                     [1,0,0,0,0].
#                     It is possible also to follow the little-endian
#                     bit ordering by using the bitorder=1 parameter:
#                     Bits('\x01\x0f',size=13,bitorder=1) is sequence
#                     [1,0,0,0,0,0,0,0,1,1,1,1,0]
# Bits can be represented as follows:
#  - human-readable string of chars : str(Bits('\x80',5)) =>  '10000'
#  - human-readable dot alternative : Bits('\x80',5).todots() =>  '|.    |'
#  - the bit sequence as a list: Bits('\x80',5).bitlist() = [1,0,0,0,0]
#  - integer : using internal ival field is not recommended, use Bits.int()
#  - raw bitstream as a bytestring: Bits('\x82',5).bytes() => '\x80'.
#    (note that if size is not a multiple of 8, the bitstream is naturally
#     extended with 0 bit padding). Again, bit0 is MSB of 1st byte.
#  - raw little-endian "packed" bytestring: the struct.pack extension
#     to encode the sequence as a little-endian arbitrary long integer is
#     provided by function pack in module bits.
class Bits(object):
  __slots__ = ['ival','__sz','mask']

  def __init__(self,v,size=None,bitorder=-1):
    self.ival = self.__sz = self.mask = 0
    if isinstance(v,Bits):
      self.ival = v.ival
      self.__sz = v.size
      self.mask = v.mask
    elif isinstance(v,IntType):
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
    if size!=None: self.size = size

  def load(self,v,bitorder=-1):
    bytestr = newbytes(v)
    self.size = len(bytestr)*8
    if bitorder==-1:
      l = [reverse_byte(c) for c in bytestr]
    else:
      l = bytestr
    v = 0
    for o in reversed(l):
      v = (v<<8) | o
    self.ival = v

  def __len__(self):
    return self.size

  def bit(self,i):
    if 0 <= i < self.__sz:
      return (self.ival>>i)&0x1
    elif 0<= -i <= self.__sz:
      return (self.ival>>(self.__sz+i))&0x1
    else:
      raise IndexError

  def int(self,sign=1):
    if sign==-1 and self.bit(-1)==1:
      return -(self.ival^self.mask)-1
    return self.ival&self.mask

  def __int__(self):
    return self.int()

  def __index__(self):
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

  # binary string representation, bit0 1st.
  def __str__(self):
    xval = ("%x"%(self.ival&self.mask)).zfill(self.__sz//4+1)
    s = [hextab_r[int(x,16)] for x in xval]
    s.reverse()
    return u''.join(s)[:self.__sz]

  # byte string representation, bit0 1st (crypto notation).
  def __bytes__(self):
    v = self.ival&self.mask
    i = 0
    s = []
    while i<self.__sz:
      s.append(reverse_byte(v&0xff))
      v = v>>8
      i += 8
    return newbytes(s)

  def bytes(self):
    return self.__bytes__()

  def hex(self):
    return codecs.encode(self.__bytes__(),'hex')

  def split(self,subsize,bigend=False):
    l = []
    i = 0
    while i<self.__sz:
      l.append(self[i:i+subsize])
      i += subsize
    if bigend: l.reverse()
    return l

  def todots(self):
    return u'|%s|'%str(self).replace('0',' ').replace('1','.')

# Basic comparison method ('is' operator), falls back to integer comparison.
#------------------------------------------------------------------------------
  def __cmp__(self,a):
    if not isinstance(a,Bits): raise AttributeError
    if self.size != a.size: raise ValueError
    return cmp(self.ival,a.ival)

# Enhanced comparison methods ('==' and '!=' operators).
#------------------------------------------------------------------------------
  def __eq__(self,a):
    if isinstance(a,Bits): a=a.ival
    return (self.ival==a)
#------------------------------------------------------------------------------
  def __ne__(self,a):
    if isinstance(a,Bits): a=a.ival
    return (self.ival!=a)

# Iterator for the class. Enables 'for b in self' expressions.
#------------------------------------------------------------------------------
  def __iter__(self):
    for x in range(self.size):
      yield self.bit(x)

# getitem operator defines b[i], b[i:j] and b[list] which returns the requested
# bit values as a int (0,1) or a list of such ints.
#------------------------------------------------------------------------------
  def __getitem__(self,i):
    if isinstance(i,IntType):
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

# setitem operator defines b[i], b[i:j] and b[list] which allow to affect new
# values to these bits, from another object, int value or a bit list.
#------------------------------------------------------------------------------
  def __setitem__(self,i,v):
    if isinstance(i,IntType):
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

# unary bitwise operators. The result is a new object which has same length.
#------------------------------------------------------------------------------
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
    if size>self.size:
      self.size = size
    return self

  def signextend(self,size):
    if size>self.size:
      m = self.mask
      s = self[-1]
      self.size = size
      if s==1:
        m ^= self.mask
        self.ival |= m
    return self

  def extend(self,sign,size):
    return self.signextend(size) if sign is True else self.zeroextend(size)

# binary operators, rvalue and lvalue implementations.
# (Note that resulting object length is max length.
#------------------------------------------------------------------------------
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

# operator // is used for concatenation:
  def __floordiv__(self,rvalue):
    if not isinstance(rvalue,Bits):
      obj = Bits(rvalue)
    else:
      obj = rvalue
    size = self.size+obj.size
    return Bits(self.ival | obj.ival<<self.size, size)

  def bitlist(self,dir=1):
    l = list(self)
    if dir==-1: l.reverse()
    return l

# hamming weight of the object (count of 1s).
#------------------------------------------------------------------------------
  def hw(self):
    return self.bitlist().count(1)

# hamming distance to another object of same length.
#------------------------------------------------------------------------------
  def hd(self,other):
    if not isinstance(other,Bits):
      obj = Bits(other)
    else:
      obj = other
    if self.size != obj.size: raise ValueError
    return (self^obj).hw()

