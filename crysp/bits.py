#!/usr/bin/env python

from math import *
from binascii import b2a_hex,a2b_hex
import struct


class Bits:

  ival   = 0L
  size   = 1
  mask   = 0x1L

  def __init__(self,v,size=None):
    if isinstance(v,Bits):
      self.ival = v.ival
      self.size = v.size
      self.mask = v.mask
    elif isinstance(v,int) or isinstance(v,long):
      if v:
        self.ival = abs(v*1L)
        self.size = int(floor(log(self.ival)/log(2)+1))
        self.mask = (1L<<self.size) -1L
    elif isinstance(v,list):
      self.size = len(v)
      self.mask = (1L<<self.size) -1L
      for i,x in enumerate(v):
        self[i] = x
    elif isinstance(v,str):
      self.size = len(v)*8
      self.mask = (1L<<self.size) -1L
      l = map(ord,v)
      i=0
      for o in l:
        self[i:i+8] = Bits(o,8).bitlist()[::-1]
        i += 8
    if size: self.size = size

  def __len__(self):
    return self.size

  def bit(self,i):
    if i in range(self.size):
      return (self.ival>>i)&0x1L
    elif -i in range(self.size+1):
      return (self.ival>>(self.size+i))&0x1L
    else:
      raise IndexError

  def __setattr__(self,field,v):
    if field == 'size':
      self.__dict__['size'] = v
      self.__dict__['mask'] = (1L<<v) -1L
    else:
      self.__dict__[field] = v

  def __repr__(self):
    c = self.__class__
    l = self.size
    s = self.ival
    return '<%s instance with ival=%x (len=%d)>'%(c,s,l)

  # binary string representation, bit0 1st.
  def __str__(self):
    s = ''
    for i in self:
      s = s+str(i)
    return s

  # byte string representation, bit0 1st (crypto notation).
  def __hex__(self):
      s = "%x"%self[::-1].ival
      return a2b_hex(s.rjust(self.size/4,'0'))

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
      if i in range(self.size):
        if self.bit(i)==1: self.ival -= 0x1L<<i
        self.ival += (v&0x1L)<<i
      elif -i in range(self.size+1):
        p = self.size+i
        if self.bit(p)==1: self.ival -= 0x1L<<p
        self.ival += (v&0x1L)<<p
      else:
        raise IndexError
    else:
      if isinstance(i,slice):
        start,stop,step = i.indices(self.size)
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

  def __rand__(self,lvalue):
    return (self & lvalue)
  def __ror__(self,lvalue):
    return (self | lvalue)
  def __rxor__(self,lvalue):
    return (self ^ lvalue)

# operator // is used for concatenation:
  def __floordiv__(self,rvalue):
    if not isinstance(rvalue,Bits):
      obj = Bits(rvalue)
    else:
      obj = rvalue
    return Bits(self.bitlist()+obj.bitlist())

  def bitlist(self):
    return map(int,str(self))

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

