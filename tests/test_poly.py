import pytest

from crysp.poly import *

def test_Poly_001():
    x = Poly(0,64,dim=3)
    assert x.dim==3
    assert x.e(0).size==64
    for v in x: assert v==Bits(0,64)
    assert x.ival == [0,0,0]
    x[0] = 1
    x[1:3] = 2,Bits(4,64)
    y = x.split(32)
    assert y.dim == 6
    y[2,4,1] = 0,0,1
    assert y.ival[0] == 1
