# -*- coding: utf-8 -*-

# rotation operators:
#--------------------
def rol(x,n):
    return (x<<n | x>>(x.size-n))
def ror(x,n):
    return (x>>n | x<<(x.size-n))

