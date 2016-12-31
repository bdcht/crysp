import pytest

from crysp.md import *
import codecs

vectors_md4 = [(b""    ,b"31d6cfe0d16ae931b73c59d7e0c089c0"),
               (b"a"   ,b"bde52cb31de33e46245e05fbdbd6fb24"),
               (b"abc" ,b"a448017aaf21d8525fc10ae87aa6729d"),
               (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890" ,b"e33b4ddc9c38f2199c3e7b164fcc0536"),
              ]
@pytest.mark.parametrize('m,h',vectors_md4)
def test_md4_001(m,h):
    md4 = MD4()
    assert md4(m) == codecs.decode(h,'hex')

vectors_md5 = [(b""    ,b"d41d8cd98f00b204e9800998ecf8427e"),
               (b"a"   ,b"0cc175b9c0f1b6a831c399e269772661"),
               (b"abc" ,b"900150983cd24fb0d6963f7d28e17f72"),
               (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890" ,b"57edf4a22be3c955ac49da2e2107b67a"),
              ]
@pytest.mark.parametrize('m,h',vectors_md5)
def test_md5_001(m,h):
    md5 = MD5()
    assert md5(m) == codecs.decode(h,'hex')

vectors_md6_1 = [(b"abc" ,b"8854c14dc284f840ed71ad7ba542855ce189633e48c797a55121a746be48cec8"),
              ]
@pytest.mark.parametrize('m,h',vectors_md6_1)
def test_md6_001(m,h):
    md6 = MD6(256,L=64)
    md6.rounds = 5
    assert md6(m) == codecs.decode(h,'hex')

def test_md6_002():
    md6 = MD6(224,L=64,Key=b'abcde12345')
    md6.rounds = 5
    m = [codecs.decode(b"11223344556677",'hex')]*86
    m[-1] = codecs.decode(b"1122334455",'hex')
    m = b''.join(m)
    assert len(m)==600
    h = b"894cf0598ad3288ed4bb5ac5df23eba0ac388a11b7ed2e3dd5ec5131"
    assert md6(m) == codecs.decode(h,'hex')

def test_md6_003():
    md6 = MD6(256)
    m = [codecs.decode(b"11223344556677",'hex')]*115
    m[-1] = b"\x11\x22"
    m = b''.join(m)
    assert len(m)==800
    h = b"4e78ab5ec8926a3db0dcfa09ed48de6c33a7399e70f01ebfc02abb52767594e2"
    assert md6(m) == codecs.decode(h,'hex')

