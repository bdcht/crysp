# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *

class Poly(object):

  def __init__(self,v,size=0,dim=0):
      if size:
          mask = (1<<size)-1
      else:
          mask = -1
      if isinstance(v,Poly):
          mask = v.mask
          self.ival = [x&mask for x in v.ival]
      elif isinstance(v,int):
          self.ival = [v&mask]
      elif isinstance(v,(list,tuple)):
          self.ival = [int(x)&mask for x in v]
      elif isinstance(v,bytes):
          mask = 0xff
          self.ival = list(newbytes(v))
      else:
          raise TypeError
      self.mask = mask
      if dim: self.dim = dim

  @property
  def dim(self):
      if self.ival:
          return len(self.ival)
      return 0

  @dim.setter
  def dim(self,dim):
      if self.ival:
          s=len(self.ival)
          if dim<s:
              self.ival=self.ival[:dim]
          else:
              self.ival+=[0]*(dim-s)
      else:
          self.ival=[0]*dim

  @dim.deleter
  def dim(self):
      self.ival = None

  @property
  def size(self):
      if self.mask==-1: return 0
      return Bits(self.mask).size

  def __len__(self):
      return self.dim

  def e(self,i):
      if self.size:
          return Bits(self.ival[i],size=self.size)
      else:
          return self.ival[i]

  def __repr__(self):
      c = self.__class__
      r = self.size
      l = self.dim
      return '<%s instance with ring=2**%d (dim=%d)>'%(c,r,l)

  def __str__(self):
      return str(self.ival)

# Iterator for the class. Enables 'for b in self' expressions.
#------------------------------------------------------------------------------
  def __iter__(self):
      for x in range(self.dim):
          yield self.e(x)

# value comparison methods ('==' and '!=' operators).
#------------------------------------------------------------------------------
  def __eq__(self,a):
      if isinstance(a,Poly):
          if not self.dim==a.dim: return False
          return all([self.e(i)==a.e(i) for i in range(a.dim)])
      return (self.ival==a)
#------------------------------------------------------------------------------
  def __ne__(self,a):
      if isinstance(a,Poly):
          if not self.dim==a.dim: return True
          return any([self.e(i)!=a.e(i) for i in range(a.dim)])
      return (self.ival!=a)

# getitem operator defines b[i], b[i:j] and b[list] which returns the requested
# bit values as a int (0,1) or a list of such ints.
#------------------------------------------------------------------------------
  def __getitem__(self,i):
      if isinstance(i,(int,slice)):
          return Poly(self.ival[i],self.size)
      else:
          return Poly([self.ival[j] for j in i],self.size)

# setitem operator defines b[i], b[i:j] and b[list] which allow to affect new
# values to these bits, from another object, int value or a bit list.
#------------------------------------------------------------------------------
  def __setitem__(self,i,v):
      if isinstance(v,Bits): v=v.int()
      if isinstance(i,int):
          self.ival[i] = v&self.mask
      else:
          if isinstance(i,slice):
              start,stop,step = i.indices(self.dim)
              r = range(start,stop,step)
          else:
              r = i
          try:
              assert len(r)==len(v)
              for j,b in zip(r,v):
                  self[j] = b
          except (TypeError,AssertionError):
              for j,b in zip(r,Poly(v,self.size,len(r))):
                  self[j] = b

# unary bitwise operators. The result is a new object which has same length.
#------------------------------------------------------------------------------
  def __lshift__(self,n):
      res = Poly(self)
      for j in range(self.dim):
          res[j] = self.e(j)<<n
      return res
  def __rshift__(self,n):
      res = Poly(self)
      for j in range(self.dim):
          res[j] = self.e(j)>>n
      return res

# binary operators, rvalue and lvalue implementations.
# (Note that resulting object length is max length.
#------------------------------------------------------------------------------
  def __and__(self,rvalue):
      res = Poly(rvalue,size=self.size,dim=self.dim)
      for j in range(self.dim):
          res[j] = self.e(j)&res.e(j)
      return res
  def __or__(self,rvalue):
      res = Poly(rvalue,size=self.size,dim=self.dim)
      for j in range(self.dim):
          res[j] = self.e(j)|res.e(j)
      return res
  def __xor__(self,rvalue):
      res = Poly(rvalue,size=self.size,dim=self.dim)
      for j in range(self.dim):
          res[j] = self.e(j)^res.e(j)
      return res
  def __add__(self,rvalue):
      res = Poly(rvalue,size=self.size,dim=self.dim)
      for j in range(self.dim):
          res[j] = self.e(j)+res.e(j)
      return res
  def __sub__(self,rvalue):
      res = Poly(rvalue,size=self.size,dim=self.dim)
      for j in range(self.dim):
          res[j] = self.e(j)-res.e(j)
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
    return (self - lvalue)

# operator // is used for concatenation:
  def __floordiv__(self,rvalue):
      res = Poly(rvalue,self.size)
      res.ival = self.ival+res.ival
      return res

  def split(self,newsize,bigend=False):
      if newsize==self.size: return self
      l = []
      for x in self: l.extend(x.split(newsize,bigend))
      return Poly([x.int() for x in l],size=newsize)

