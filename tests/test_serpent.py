import pytest
import codecs
from crysp.serpent import *

# test Serpent block cipher from NESSIE test vectors:
# ---------------------------------------------------

# set 1, vector 0:
def test_serpent_001():
    K = Bits(codecs.decode("8000000000000000000000000000000000000000000000000000000000000000",'hex'),bitorder=1)
    P = codecs.decode("00000000000000000000000000000000",'hex')
    S = Serpent(K)
    C = S.enc(P)
    assert C==codecs.decode("A223AA1288463C0E2BE38EBD825616C0",'hex')
    assert S.dec(C)==P

# set 1, vector 1:
def test_serpent_002():
    K = Bits(codecs.decode("4000000000000000000000000000000000000000000000000000000000000000",'hex'),bitorder=1)
    P = codecs.decode("00000000000000000000000000000000",'hex')
    S = Serpent(K)
    C = S.enc(P)
    assert C==codecs.decode("EAE1D405570174DF7DF2F9966D509159",'hex')
    assert S.dec(C)==P

# set 1, vector 2:
def test_serpent_003():
    K = Bits(codecs.decode("1111111111111111111111111111111111111111111111111111111111111111",'hex'),bitorder=1)
    P = codecs.decode("11111111111111111111111111111111",'hex')
    S = Serpent(K)
    C = S.enc(P)
    assert C==codecs.decode("A482EAA5D5771F2FDB2EA1A5F141B9E2",'hex')
    assert S.dec(C)==P
