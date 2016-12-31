import pytest
from crysp.crc import *
from binascii import b2a_hex

D = {
        b"": 0x0,
        b"a": 0xe8b7be43,
        b"abc": 0x352441c2,
        b"message digest": 0x20159d7f,
        b"Toto": 0xB0FE0BCF,
    }

@pytest.mark.parametrize('k,v',D.items())
def test_crc(k,v):
    assert crc32(k)==v
