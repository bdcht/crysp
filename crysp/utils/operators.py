#!/usr/bin/env python
# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license

# rotation operators:
#--------------------
def rol(x,n):
    return (x<<n | x>>(x.size-n))
def ror(x,n):
    return (x>>n | x<<(x.size-n))

