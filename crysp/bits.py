#!/usr/bin/env python

from math import floor,log

# reverse all bits in a byte:
def reverse_byte(b):
    return (b * 0x0202020202L & 0x010884422010L) % 1023

def pack(obj,fmt='<L'):
    assert fmt in ['<L']
    s = (chr(x.ival&0xff) for x in obj.split(8))
    return ''.join(s)


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
#  - int/long values: bits are ordered from LSB to MSB.
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
#  - raw bitstream as a bytestring: hex(Bits('\x82',5) => '\x80'.
#    (note that if size is not a multiple of 8, the bitstream is naturally
#     extended with 0 bit padding). Again, bit0 is MSB of 1st byte.
#  - raw little-endian "packed" bytestring: the struct.pack extension
#     to encode the sequence as a little-endian arbitrary long integer is
#     provided by function pack in module bits.
class Bits(object):
  __slots__ = ['ival','__sz','mask']

  def __init__(self,v,size=None,bitorder=-1):
    self.ival = self.__sz = self.mask = 0L
    if isinstance(v,Bits):
      self.ival = v.ival
      self.__sz = v.size
      self.mask = v.mask
    elif isinstance(v,int) or isinstance(v,long):
      self.ival = abs(v*1L)
      if self.ival>0:
        self.size = int(floor(log(self.ival)/log(2)+1))
    elif isinstance(v,list):
      self.size = len(v)
      for i,x in enumerate(v):
        self[i] = x
    elif isinstance(v,str):
      self.load(v,bitorder)
    if size!=None: self.size = size

  def load(self,bytestr,bitorder=-1):
    self.size = len(bytestr)*8
    l = map(ord,bytestr)
    i=0
    for o in l:
      self[i:i+8] = Bits(o,8).bitlist(bitorder)
      i += 8

  def __len__(self):
    return self.size

  def bit(self,i):
    if 0 <= i < self.__sz:
      return (self.ival>>i)&0x1L
    elif 0<= -i <= self.__sz:
      return (self.ival>>(self.__sz+i))&0x1L
    else:
      raise IndexError

  def int(self,sign=1):
    if sign==-1 and self[-1]==1:
      return -(self.ival^self.mask)-1
    return self.ival&self.mask

  @property
  def size(self):
      return self.__sz

  @size.setter
  def size(self,v):
      self.__sz = v
      self.mask = (1L<<v)-1L

  def __repr__(self):
    c = self.__class__
    l = self.__sz
    s = self.ival
    return '<%s instance with ival=%x (len=%d)>'%(c,s,l)

  # binary string representation, bit0 1st.
  def __str__(self):
    xval = ("%x"%(self.ival&self.mask)).zfill(self.__sz/4+1)
    s = [hextab_r[int(x,16)] for x in xval]
    s.reverse()
    return ''.join(s)[:self.__sz]

  # byte string representation, bit0 1st (crypto notation).
  def __hex__(self):
      v = self.ival&self.mask
      i = 0
      s = []
      while i<self.__sz:
          s.append(chr(reverse_byte(v&0xff)))
          v = v>>8
          i += 8
      return ''.join(s)

  def split(self,subsize):
      l = []
      i = 0
      while i<self.__sz:
          l.append(self[i:i+subsize])
          i += subsize
      return l

  def todots(self):
    return '|%s|'%str(self).replace('0',' ').replace('1','.')

# Basic comparison method ('is' operator), falls back to integer comparison.
#------------------------------------------------------------------------------
  def __cmp__(self,a):
    if not isinstance(a,Bits): raise AttributeError
    if self.size != a.size: raise ValueError
    return cmp(self.ival,a.ival)

# Enhanced comparison methods ('==' and '<>' operators).
#------------------------------------------------------------------------------
  def __eq__(self,a):
    if isinstance(a,Bits): a=a.ival
    return (self.ival==a)
#------------------------------------------------------------------------------
  def __ne__(self,a):
    if isinstance(a,Bits): a=a.ival
    return (self.ival<>a)

# Iterator for the class. Enables 'for b in self' expressions.
#------------------------------------------------------------------------------
  def __iter__(self):
    for x in range(self.size):
      yield self.bit(x)

# getitem operator defines b[i], b[i:j] and b[list] which returns the requested
# bit values as a long (0L,1L) or a list of such longs.
#------------------------------------------------------------------------------
  def __getitem__(self,i):
    if isinstance(i,int):
      return Bits(self.bit(i),1)
    elif isinstance(i,slice):
      return Bits(self.bitlist()[i])
    else:
      s=[]
      for x in i:
          s.append(self.bit(x))
      return Bits(s)

# setitem operator defines b[i], b[i:j] and b[list] which allow to affect new
# values to these bits, from another object, int/long value or a bit list.
#------------------------------------------------------------------------------
  def __setitem__(self,i,v):
    if isinstance(i,int):
      assert v in (0,1)
      if i in range(self.__sz):
        if self.bit(i)==1: self.ival -= 0x1L<<i
        self.ival += (v&0x1L)<<i
      elif -i in range(self.__sz+1):
        p = self.__sz+i
        if self.bit(p)==1: self.ival -= 0x1L<<p
        self.ival += (v&0x1L)<<p
      else:
        raise IndexError
    else:
      if isinstance(i,slice):
        start,stop,step = i.indices(self.__sz)
        r = range(start,stop,step)
      else:
        r = i
      try:
        assert len(r)==len(v)
        for j,b in zip(r,v):
          self[j] = b
      except (TypeError,AssertionError):
        for j,b in zip(r,Bits(v,len(r))):
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
    return Bits(self.bitlist()+obj.bitlist())

  def bitlist(self,dir=1):
    l = map(int,str(self))
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

