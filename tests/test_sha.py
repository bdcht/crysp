import pytest

from crysp.sha import *

vectors_sha1 = [(""    ,"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"),
                ("a"   ,"86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8"),
                ("abc" ,"A9993E364706816ABA3E25717850C26C9CD0D89D"),
               ]
@pytest.mark.parametrize('m,h',vectors_sha1)
def test_sha1_001(m,h):
    sha1 = SHA1()
    assert sha1(m).encode('hex') == h.lower()

def test_sha1_002():
    href = '\x00\x98\xba\x82K\\\x16B{\xd7\xa1\x12*ZD*%\xecdM'
    assert SHA1()('a'*64) == href
    sha1 = SHA1()
    sha1.update('a'*64)
    b = sha1.padblock('',bitlen=512)
    assert b[0]=='\x80' and b[-2]==chr(0x2)
    assert sha1.update(b) == href
