import pytest

from crysp.bits import *

def test_import_bitstream():
    x = Bits(b'\x01\x05\x82')
    y = Bits(0x41a080,size=24)
    assert x.ival == 0x41a080
    assert len(x) == 24
    assert x.hex()==b'010582'
    assert x == y
    assert pack(y)==b'\x80\xa0A'

def test_import_bytes_LE():
    x = Bits(b'\x01\x05\x82',bitorder=1)
    y = Bits(0x020501,20)
    assert x.size==24
    x.size = 20
    assert x.mask == y.mask == 0x0fffff
    assert x==y
    assert pack(x)==b'\x01\x05\x02'

def test_import_bytes_BE():
    x = Bits(b'\x01\x05\x82',bitorder=0)
    y = Bits(0x010582,32)
    assert x.size==24
    x.size = 32
    assert x.mask == y.mask
    assert x==y
    assert pack(x)==b'\x82\x05\x01\x00'
    assert pack(x,'>L')==b'\x00\x01\x05\x82'

def test_import_bytes_PDP():
    x = Bits(b'\x0b\x0a\x0d\x0c'[::-1],bitorder=2)
    y = Bits(0x0a0b0c0d,32)
    assert x==y

def test_import_bytes_Honeywell316():
    x = Bits(b'\x0c\x0d\x0a\x0b',bitorder=2)
    y = Bits(0x0a0b0c0d,32)
    assert x==y

