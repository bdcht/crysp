import pytest
from crysp.serpent import *

# test Serpent block cipher from NESSIE test vectors:
# ---------------------------------------------------

# set 1, vector 0:
def test_serpent_001():
    K = Bits("8000000000000000000000000000000000000000000000000000000000000000".decode('hex'),bitorder=1)
    P = "00000000000000000000000000000000".decode('hex')
    S = Serpent(K)
    C = S.enc(P)
    assert C.encode('hex')=="A223AA1288463C0E2BE38EBD825616C0".lower()
    assert S.dec(C)==P

# set 1, vector 1:
def test_serpent_002():
    K = Bits("4000000000000000000000000000000000000000000000000000000000000000".decode('hex'),bitorder=1)
    P = "00000000000000000000000000000000".decode('hex')
    S = Serpent(K)
    C = S.enc(P)
    assert C.encode('hex')=="EAE1D405570174DF7DF2F9966D509159".lower()
    assert S.dec(C)==P

# set 1, vector 2:
def test_serpent_003():
    K = Bits("1111111111111111111111111111111111111111111111111111111111111111".decode('hex'),bitorder=1)
    P = "11111111111111111111111111111111".decode('hex')
    S = Serpent(K)
    C = S.enc(P)
    assert C.encode('hex')=="A482EAA5D5771F2FDB2EA1A5F141B9E2".lower()
    assert S.dec(C)==P
