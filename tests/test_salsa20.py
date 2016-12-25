import pytest

from crysp.salsa20 import *

L = [211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136, 49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207, 31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104, 54]
m = newbytes(L)

k0 = list(range(1,17))
k1 = list(range(201,217))
n  = list(range(101,117))
v  = Bits(newbytes(n),bitorder=1)

def test_salsa20_000_hash():
    r = Salsa20().hash(m)
    rl = list(newbytes(r))
    assert rl[0:3] == [109,42,178]
    assert rl[-3:] == [19,48,202]

def test_salsa20_001_cipher():
    K = Bits(newbytes(k0+k1),bitorder=1)
    S = Salsa20(K)
    S.p[6:10] = v.split(32)
    res = list(newbytes(pack(S.core(S.p))))
    assert res[0:5] == [69,37,68,39,41]
    assert res[-5:] == [236,234,103,246,74]

def test_salsa20_002_cipher():
    K = Bits(newbytes(k0),bitorder=1)
    S = Salsa20(K)
    S.p[6:10] = v.split(32)
    res = list(newbytes(pack(S.core(S.p))))
    assert res[0:5] == [39,173,46,248,30]
    assert res[-5:] == [181,104,182,177,193]
