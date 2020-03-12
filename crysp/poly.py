# -*- coding: utf-8 -*-

# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

from crysp.bits import *

__all__ = ['struct','Bits','reverse_byte','pack','unpack','SubPoly','Poly']

class SubPoly(object):
  """The SubPoly class represents an ordered sequence of elements of a ring.

  Args:
      v: the input value, either a Poly, int, list/tuple or bytes.
      size(Optional[int]): the bit size of elements (definition of the ring). Default to 0 (ring = Z)
      dim(Optional[int]): the dimension of the ordered sequence (Polynomial).

  Attributes:
      ival (list): the internal sequence of elements

 """
  def __init__(self,v,size=0,dim=0):
      if size:
          mask = (1<<size)-1
      else:
          mask = -1
      if isinstance(v,SubPoly):
          mask = v.mask
          self.ival = [x&mask for x in v.ival]
      elif isinstance(v,int):
          self.ival = [v&mask]
      elif isinstance(v,Bits):
          self.ival = [v.int()&mask]
      elif isinstance(v,(list,tuple)):
          self.ival = [int(x)&mask for x in v]
      elif isinstance(v,bytes):
          mask = 0xff
          self.ival = list(bytes(v))
      else:
          raise TypeError
      self.mask = mask
      if dim>0: self.dim = dim
      self.__d = None

  @property
  def dim(self):
      if self.ival:
          return len(self.ival)
      return 0

  @dim.setter
  def dim(self,dim):
      assert dim>0
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

  @property
  def degree(self):
      if self.__d: return self.__d
      d = self.dim
      while d>0 and self.ival[d-1]==0:
          d = d-1
      self.__d = d-1
      return self.__d

  def e(self,i):
      if i<self.dim: v=self.ival[i]
      else: v=0
      if self.size:
          return Bits(v,size=self.size)
      else:
          return v

  def __repr__(self):
      c = self.__class__
      r = self.size
      l = self.dim
      return '<%s instance with ring=2**%d (dim=%d)>'%(c,r,l)

  def __str__(self):
      return str(self.ival)

  def redim(self):
      self.dim = self.degree+1
      return self

  def indices(self,s):
      sta,sto,step = s.indices(len(self.ival))
      if step<0: raise ValueError
      if s.stop and s.stop>sto: sto=s.stop
      return range(sta,sto,step)

  def span(self,s):
      C = self.indices(s)
      return [self.e(i) for i in C]

# Iterator for the class. Enables 'for b in self' expressions.
#------------------------------------------------------------------------------
  def __iter__(self):
      for x in range(self.dim):
          yield self.e(x)

# value comparison methods ('==' and '!=' operators).
#------------------------------------------------------------------------------
  def __eq__(self,a):
      if self.dim==a.dim: return not any((x-y for (x,y) in zip(self.ival,a.ival)))
      return (self-a).is_zero()

  def __ne__(self,a):
      if self.dim==a.dim: return any((x-y for (x,y) in zip(self.ival,a.ival)))
      return not (self-a).is_zero()

  def is_zero(self):
      return not any(self.ival)

  def __neg__(self):
      return self.__class__([-x for x in self.ival])


# getitem operator defines b[i], b[i:j] and b[list] which returns the requested
# coefficients as a Poly instance
#------------------------------------------------------------------------------
  def __getitem__(self,i):
      if isinstance(i,int):
          res = self.__class__(0,self.size,max(self.dim,i))
          res[i] = self.e(i)
      elif isinstance(i,slice):
          s = self.indices(i)
          if len(s)==0: return None
          res = self.__class__(0,self.size,s[-1])
          for i in s: res[i] = self.e(i)
      else:
          res = self.__class__(0,self.size,max(i))
          for j in i: res[j] = self.e(j)
      return res

# setitem operator defines b[i], b[i:j] and b[list] which allow to affect new
# values to these coeffs, from another object, int or list.
#------------------------------------------------------------------------------
  def __setitem__(self,i,v):
      if isinstance(v,Bits):
          v=v.int()
      if isinstance(i,int):
          self.ival[i] = v&self.mask
          return
      if isinstance(i,slice):
          r = self.indices(i)
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
      assert self.size==rvalue.size
      res = self.__class__(0,size=self.size,dim=max(self.dim,rvalue.dim))
      for j in range(res.dim):
          res[j] = self.e(j)&rvalue.e(j)
      return res
  def __or__(self,rvalue):
      assert self.size==rvalue.size
      res = self.__class__(0,size=self.size,dim=max(self.dim,rvalue.dim))
      for j in range(self.dim):
          res[j] = self.e(j)|rvalue.e(j)
      return res
  def __xor__(self,rvalue):
      assert self.size==rvalue.size
      res = self.__class__(0,size=self.size,dim=max(self.dim,rvalue.dim))
      for j in range(self.dim):
          res[j] = self.e(j)^rvalue.e(j)
      return res
  def __add__(self,rvalue):
      assert self.size==rvalue.size
      res = self.__class__(0,size=self.size,dim=max(self.dim,rvalue.dim))
      for j in range(self.dim):
          res[j] = self.e(j)+rvalue.e(j)
      return res
  def __sub__(self,rvalue):
      assert self.size==rvalue.size
      res = self.__class__(0,size=self.size,dim=max(self.dim,rvalue.dim))
      for j in range(self.dim):
          res[j] = self.e(j)-rvalue.e(j)
      return res
  def __mul__(self,rvalue):
      res = self.__class__(0,size=self.size,dim=self.dim+rvalue.dim)
      for j in range(self.dim):
          for r in range(rvalue.dim):
              res[j+r] += self.e(j)*rvalue.e(r)
      return res
  def __divmod__(self,rvalue):
      if rvalue.is_zero(): raise ZeroDivisionError
      q,r = 0, self.__class__(self)
      ddeg = rvalue.degree
      ldc = rvalue.e(ddeg)
      mxp = r.degree - ddeg
      while mxp >= 0:
          mdr = self.__class__([0]*mxp + [r.e(r.degree)/ldc], size=self.size)
          mdr.redim()
          q += mdr
          r -= mdr*rvalue
          mxp = r.degree - ddeg
      return (q,r)

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
  def __rmul__(self,lvalue):
    return (self * lvalue)

# operator // is used for concatenation:
  def __floordiv__(self,rvalue):
      res = self.__class__(0,self.size)
      res.ival = self.ival+rvalue.ival
      return res

  def split(self,newsize,bigend=False):
      if newsize==self.size: return self
      l = []
      for x in self: l.extend(x.split(newsize,bigend))
      return self.__class__([x.int() for x in l],size=newsize)


class Poly(SubPoly):

  def __getitem__(self,i):
      if isinstance(i,int):
          return Poly(self.ival[i],self.size)
      elif isinstance(i,slice):
          return Poly(self.span(i),self.size)
      else:
          return Poly([self.ival[j] for j in i],self.size)

