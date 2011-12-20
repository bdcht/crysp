#!/usr/bin/env python

from math import *
from binascii import b2a_hex,a2b_hex
import struct


#------------------------------------------------------------------------------
# All vectors are LSB first (little endian)
# Check for the Bitseq for a bit flow class (bitseq.py)
#------------------------------------------------------------------------------
class Bits:

  ival   = 0L
  size   = 1
  mask   = 0x1L

# creator: objects are imported from ints, longs and lists.
#------------------------------------------------------------------------------
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
      for i in range(self.size):
        assert v[i] in [0,1]
        self[i] = v[i]
      self.mask = (1L<<self.size) -1L
    elif isinstance(v,str):
      self.size = len(v)*8
      self.mask = (1L<<self.size) -1L
      l = map(ord,v)
      i=0
      for o in l:
        self[i:i+8] = Bits(o,8)[::-1]
        i += 8
    if size: self.size = size

# bit length of the object.
# Defaults to the minimum digits needed to store the object value, but can be
# set manually to the desired length.
# Notice that the bit length is really size and not mask, so mask must follow
# changes of size, not the contrary.
#------------------------------------------------------------------------------
  def __len__(self):
    return self.size
  def __setattr__(self,field,v):
    if field == 'size':
      self.__dict__['size'] = v
      self.__dict__['mask'] = (1L<<v) -1L
    else:
      self.__dict__[field] = v

# raw representation of the bit vector
# Uses dots for '1' and spaces for '0', the string length is self.size.
#------------------------------------------------------------------------------
  def __repr__(self):
    c = self.__class__
    l = self.size
    s = self.ival
    return '<%s instance with ival=%x (len=%d)>'%(c,s,l)

# binary string converter.
# (The string is LSB first)
#------------------------------------------------------------------------------
  def __str__(self):
    s = ''
    for i in self:
      s = s+str(i)
    return s

  def __hex__(self):
      s = "%x"%Bits(self[::-1]).ival
      return a2b_hex(s.ljust(self.size/4,'0'))

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
      yield self.__getitem__(x)

# getitem operator defines b[i], b[i:j] and b[list] which returns the requested
# bit values as a long (0L,1L) or a list of such longs.
#------------------------------------------------------------------------------
  def __getitem__(self,i):
    if type(i)==type([]):
      s = []
      for x in i:
        s.append(self[x])
      return s
    elif isinstance(i,slice):
      s = []
      start,stop,step = i.indices(self.size)
      for x in range(start,stop,step):
        s.append(self[x])
      return s
    elif isinstance(i,int):
      if i in range(self.size):
        return (self.ival>>i)&0x1L
      elif -i in range(self.size+1):
        return (self.ival>>(self.size+i))&0x1L
      else:
        raise IndexError
    else:
      raise TypeError

# setitem operator defines b[i], b[i:j] and b[list] which allow to affect new
# values to these bits, from another object, int/long value or a bit list.
#------------------------------------------------------------------------------
  def __setitem__(self,i,v):
    if isinstance(v,Bits):
      lv = v[:]
    elif isinstance(v,int) or isinstance(v,long):
      Vbits = Bits(v)
      lv = Vbits[:]
    else:
      lv = v
    if not isinstance(lv,list):
      raise TypeError

    if isinstance(i,list):
      for x in range(len(i)):
        self[i[x]] = lv[x]
    elif isinstance(i,slice):
      start,stop,step = i.indices(self.size)
      r = range(start,stop,step)
      if len(r)!=len(lv):
        assert step==1
        stop = min(len(r),len(lv))
        r = range(start,stop,step)
      for x in range(len(r)):
          self[r[x]] = lv[x]
    elif isinstance(i,int):
      if i in range(self.size):
        if self[i]==1: self.ival -= 0x1L<<i
        self.ival += (lv[0]&0x1L)<<i
      elif -i in range(self.size+1):
        p = self.size+i
        if self[p]==1: self.ival -= 0x1L<<p
        self.ival += (lv[0]&0x1L)<<p
      else:
        raise IndexError
    else:
      raise TypeError

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

# hamming weight of the object (count of 1s).
#------------------------------------------------------------------------------
  def hw(self):
    return self[:].count(1)

# hamming distance to another object of same length.
#------------------------------------------------------------------------------
  def hd(self,other):
    if not isinstance(other,Bits):
      obj = Bits(other)
    else:
      obj = other
    if self.size != obj.size: raise ValueError
    return (self^obj).hw()

