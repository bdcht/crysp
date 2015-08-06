import pytest
from crysp.crc import *
from binascii import b2a_hex

D = {
        "": 0x0,
        "a": 0xe8b7be43L,
        "abc": 0x352441c2L,
        "message digest": 0x20159d7fL,
        "Toto": 0xB0FE0BCFL,
    }

@pytest.mark.parametrize('k,v',D.items())
def test_crc(k,v):
    assert crc32(k)==v
