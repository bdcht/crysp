import pytest

from crysp.md import *

vectors_md4 = [(""    ,"31d6cfe0d16ae931b73c59d7e0c089c0"),
               ("a"   ,"bde52cb31de33e46245e05fbdbd6fb24"),
               ("abc" ,"a448017aaf21d8525fc10ae87aa6729d"),
               ("12345678901234567890123456789012345678901234567890123456789012345678901234567890" ,"e33b4ddc9c38f2199c3e7b164fcc0536"),
              ]
@pytest.mark.parametrize('m,h',vectors_md4)
def test_md4_001(m,h):
    md4 = MD4()
    assert md4(m).encode('hex') == h

vectors_md5 = [(""    ,"d41d8cd98f00b204e9800998ecf8427e"),
               ("a"   ,"0cc175b9c0f1b6a831c399e269772661"),
               ("abc" ,"900150983cd24fb0d6963f7d28e17f72"),
               ("12345678901234567890123456789012345678901234567890123456789012345678901234567890" ,"57edf4a22be3c955ac49da2e2107b67a"),
              ]
@pytest.mark.parametrize('m,h',vectors_md5)
def test_md5_001(m,h):
    md5 = MD5()
    assert md5(m).encode('hex') == h

