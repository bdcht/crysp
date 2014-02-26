#!/usr/bin/env python

from crysp.bits import *

x = Bits('\x01\x05\x82')
y = Bits(0x41a080,size=24)

assert x.ival == 0x41a080
assert len(x) == 24
assert hex(x)=='\x01\x05\x82'
assert x == y

assert pack(y)=='\x80\xa0A'
