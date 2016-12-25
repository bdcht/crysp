#!/usr/bin/env python
from __future__ import print_function

# This code is part of crysp
# Copyright (C) 2009 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license

import struct
from crysp.bits import *

#CRC32 :
#=======
#divider:
POLY32_1 = Bits(0xEDB88320,32)
#CRC32 inverse of x^32 in the field:
POLY32_1i= Bits(0x5B358FD3,32)

def crc_table(P):
  table = list(range(256))
  for n in table:
    c=Bits(n,P.size)
    for k in range(8):
      if (c[0])!=0 : c = P^(c>>1)
      else         : c =    c>>1
    table[n] = c
  return table

def crc_back_table(P):
  table = {}
  for n in range(256):
    c=Bits(n<<(P.size-8),P.size)
    for k in range(8):
      if (c[-1])!=0 : c = ((c^P)<<1)|1
      else          : c = c<<1
    table[n] = c
  return table

#precomputed table for byte processing:
TABLE32_1 = crc_table(POLY32_1)
#precomputed backward table for byte processing:
TABLE32_1b= crc_back_table(POLY32_1)

def crc(data,table,Xinit=0,Xfinal=None):
  if not isinstance(data,bytes):
    print("crc: bytes input required")
    return None
  r = Bits(Xinit,table[0].size)
  for b in newbytes(data):
    p = table[(r.ival^b)&0xff]
    r = (r>>8)^p
  if Xfinal:
    r = r^Bits(Xfinal)
  return r.ival

def crc_back_pos(data,pos,table,Xfinal,c):
  if not isinstance(data,bytes):
    print("crc: bytes input required")
    return None
  data = newbytes(data)
  if not (0<=pos<len(data)):
    print("crc_back: pos error")
    return None
  N = table[0].size
  r = Bits(Xfinal,N)
  r = r^c
  for b in data[pos::][::-1]:
    p = table[r.ival>>(N-8)]^b
    r = (r<<8)^p
  return r.ival

# CRC-32:
def crc32(data):
  return crc(data,TABLE32_1,0xffffffff)^0xffffffff

# CRC-32 backward to pos. 
# Returned value is before final XOR (0xffffffff)
def crc32_back_pos(data,pos,c):
  return crc_back_pos(data,pos,TABLE32_1b,0xffffffff,c)

# CRC-32 fix last 4 bytes in data to obtain target.
def crc32_fix(data,target):
  if isinstance(target,str):
    target = int(target,0)
  t = target^0xffffffff
  # compute a = t*inv(x^32) mod POLY32_1.
  a = 0
  for i in range(32):
    if a&1: a = (a>>1)^POLY32_1.ival
    else  : a =  a>>1
    if t&1: a = a^POLY32_1i.ival
    t=t>>1
  a = a^crc(data[:-4],TABLE32_1,0xffffffff)
  return data[:-4]+struct.pack('I',a)

# CRC-32 alternate fix 4 bytes in data at position pos.
def crc32_fix_pos(data,pos,target):
  c_fw = crc(data[:pos],TABLE32_1,0xffffffff)
  c_bw = crc32_back_pos(struct.pack('I',c_fw)+data[pos+4:],0,target)
  return data[:pos]+struct.pack('I',c_bw)+data[pos+4:]

if __name__ == '__main__':
  import sys
  if len(sys.argv)<2:
    print("Usage: crc [[-pos k] -crc target] <message>")
    print("  pos: position in message where to fix 4 bytes (default to last 4 bytes)")
    print("  crc: target crc32 value, integer or '0x...' string format.")
    sys.exit(1)
  data = sys.argv.pop()
  sys.argv.pop(0)
  pos = None
  target = None
  while len(sys.argv)>0:
    arg = sys.argv.pop(0)
    if (arg=='-pos') and len(sys.argv)>0: pos = int(sys.argv.pop(0))
    if (arg=='-crc') and len(sys.argv)>0: target = int(sys.argv.pop(0),0)
  print("data   =",data)
  print("pos    =",pos)
  print("target =",target)
  r1 = crc32(data)
  print("original crc32 = 0x%08x (%d)" %(r1,r1))
  if target:
    if pos: newdata = crc32_fix_pos(data,pos,target)
    else  : newdata = crc32_fix(data,target)
    print(newdata)
    r2 = crc32(newdata)
    print("new crc32 = 0x%08x (%d)" %(r2,r2))
