#!/usr/bin/env python

from math import *
from binascii import b2a_hex,a2b_hex
import struct


class Poly(object):

  ival   = None
  ring   = 0

  @property
  def size(self):
      if self.ival:
          return len(self.ival)
      return 0

  @size.setter
  def size(self,size):
      if self.ival:
          s=len(self.ival)
          if size<s:
              self.ival=self.ival[:size]
          else:
              self.ival+=[0]*(size-s)
      else:
          self.ival=[0]*size
  @size.deleter
  def size(self):
      self.ival = None

  def __init__(self,v,ring=0,size=None):
      if isinstance(v,Poly):
          self.ival = v.ival[:]
          self.ring = v.ring
      elif isinstance(v,int):
          self.size = 1
          self.ival = [v]
          if ring: self.ring = ring
      elif isinstance(v,list):
          self.size = len(v)
          if ring: self.ring = ring
          for i,x in enumerate(v):
              self.ival[i] = x
      elif isinstance(v,str):
        self.size = len(v)
        self.ring = 256
        l = map(ord,v)
        for i,x in enumerate(l):
            self.ival[i] = x
      else:
            NotImplemented
      if size: self.size = size


  def __len__(self):
    return self.size

  def e(self,i):
      if self.ring:
          return self.ival[i]%self.ring
      else:
          return self.ival[i]

  def __repr__(self):
    c = self.__class__
    r = self.ring
    l = self.size
    return '<%s instance with ring=%d (len=%d)>'%(c,r,l)

  def __str__(self):
    return str(self.ival)

# Iterator for the class. Enables 'for b in self' expressions.
#------------------------------------------------------------------------------
  def __iter__(self):
    for x in range(self.size):
      yield self.e(x)

# value comparison methods ('==' and '<>' operators).
#------------------------------------------------------------------------------
  def __eq__(self,a):
    if isinstance(a,Poly):
        return False not in map(lambda x,y:x==y,self,a)
    return (self.ival==a)
#------------------------------------------------------------------------------
  def __ne__(self,a):
    if isinstance(a,Poly):
        return False not in map(lambda x,y:x<>y,self,a)
    return (self.ival<>a)

# getitem operator defines b[i], b[i:j] and b[list] which returns the requested
# bit values as a long (0L,1L) or a list of such longs.
#------------------------------------------------------------------------------
  def __getitem__(self,i):
    if isinstance(i,int):
      return Poly(self.e(i),self.ring)
    elif isinstance(i,slice):
      return Poly(self.ival[i],self.ring)
    else:
      s=[]
      for x in i:
          s.append(self.e(x))
      return Poly(s,self.ring)

# setitem operator defines b[i], b[i:j] and b[list] which allow to affect new
# values to these bits, from another object, int/long value or a bit list.
#------------------------------------------------------------------------------
  def __setitem__(self,i,v):
    if isinstance(i,int):
        if self.ring:
            self.ival[i] = v%self.ring
        else:
            self.ival[i] = v
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
        for j,b in zip(r,Poly(v,self.ring,len(r))):
          self[j] = b

# unary bitwise operators. The result is a new object which has same length.
#------------------------------------------------------------------------------
  def __lshift__(self,i):
    res = Poly(self)
    res.ival = [0]*i + res.ival
    return res
  def __rshift__(self,i):
    res = Poly(self)
    res.ival = res.ival[i:]
    return res

# binary operators, rvalue and lvalue implementations.
# (Note that resulting object length is max length.
#------------------------------------------------------------------------------
  def __and__(self,rvalue):
    if not isinstance(rvalue,Poly):
      obj = Poly(rvalue,ring=self.ring)
    else:
      obj = rvalue
    return Poly(map(lambda x,y: x&y,self.ival,obj.ival),self.ring)
  def __or__(self,rvalue):
    if not isinstance(rvalue,Poly):
      obj = Poly(rvalue,ring=self.ring)
    else:
      obj = rvalue
    return Poly(map(lambda x,y: x|y,self.ival,obj.ival),self.ring)
  def __xor__(self,rvalue):
    if not isinstance(rvalue,Poly):
      obj = Poly(rvalue,ring=self.ring)
    else:
      obj = rvalue
    return Poly(map(lambda x,y: x^y,self.ival,obj.ival),self.ring)
  def __add__(self,rvalue):
    if not isinstance(rvalue,Poly):
      obj = Poly(rvalue,ring=self.ring)
    else:
      obj = rvalue
    return Poly(map(lambda x,y: x+y,self.ival,obj.ival),self.ring)
  def __sub__(self,rvalue):
    if not isinstance(rvalue,Poly):
      obj = Poly(rvalue,ring=self.ring)
    else:
      obj = rvalue
    return Poly(map(lambda x,y: x-y,self.ival,obj.ival),self.ring)

  def __rand__(self,lvalue):
    return (self & lvalue)
  def __ror__(self,lvalue):
    return (self | lvalue)
  def __rxor__(self,lvalue):
    return (self ^ lvalue)
  def __radd__(self,lvalue):
    return (self ^ lvalue)
  def __rsub__(self,lvalue):
    return (self ^ lvalue)

# operator // is used for concatenation:
  def __floordiv__(self,rvalue):
    if not isinstance(rvalue,Poly):
      obj = Poly(rvalue,self.ring)
    else:
      obj = rvalue
    return Poly(self.ival+obj.ival,self.ring)

  def poly(self):
    if self.ring: return [x%self.ring for x in self.ival]
    return self.ival[:]

