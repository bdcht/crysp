#!/usr/bin/env python
# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license
from functools import reduce

# rotation operators:
#--------------------
def rol(x,n):
    return (x<<n | x>>(x.size-n))
def ror(x,n):
    return (x>>n | x<<(x.size-n))


# concatenation:
def concat(L,bigend=False):
    if len(L)==1: return L[0]
    if bigend: L = reversed(L)
    return reduce(lambda x,y: x//y, L)
