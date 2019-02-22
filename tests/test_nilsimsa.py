import pytest
import codecs
from crysp.nilsimsa import *

vectors_2 = [(b"abcdefgh" ,
              b"14c8118000000000030800000004042004189020001308014088003280000078"),
             (b"This is a much more ridiculous test because of 21347597.",
              b"5d9c6a6b22384bcd524a8d414d82237777433fc1a07a02c3e06985d96ecdf8fb"),
            ]
@pytest.mark.parametrize('m,h',vectors_2)
def test_nilsimsa_001(m,h):
    H = Nilsimsa()
    assert codecs.encode(H(m),'hex') == h

def test_nilsimsa_002():
    H = Nilsimsa(17)
    m = b"abcdefgh"
    assert codecs.encode(H(m),'hex') == b"001210201001000200470001180808120104800100186080000a044020020500"
    m = b"This is a much more ridiculous test because of 21347597."
    assert codecs.encode(H(m),'hex') == b"55c40c9aac438bf1b698a3a9ca3632b4d52f4cedc4f596b66fb1e0704e08aa01"

def test_nilsimsa_003():
    H = Nilsimsa()
    h1 = H(b"The rain in Spain falls mostly in the plains.")
    h2 = H(b"The rain in Spain falls mainly in the plains.")
    assert codecs.encode(h1,'hex') == b"039020eb1050188be400091130981860648e39f5b1246d8c3c3c7623801186ac"
    assert codecs.encode(h2,'hex') == b"23b000e908501883c408019410d83a60c48f1977a3246ccc3cbc7213c81104bc"
    bh1 = Bits(h1)
    bh2 = Bits(h2)
    assert bh1.hw()==94
    assert bh2.hw()==96
    assert bh1.hd(bh2)==36
