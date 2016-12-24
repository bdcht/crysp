import pytest

from crysp.padding import *

def test_blockiterator_001():
    g = blockiterator(32)
    assert g.blocklen==4
    assert g.padflag==False
    assert g.bitcnt==0
    assert g.padcnt==0
    with pytest.raises(PaddingError) as exc:
        blockiterator(33)
    assert exc.value.value == 'invalid block size'
    with pytest.raises(PaddingError) as exc:
        next(g.iterblocks(b'AAA',padding=False))
    assert exc.value.value == 'input not a multiple of block size'

def test_blockiterator_002():
    g = blockiterator(32)
    B = list(g.iterblocks(b'A'*4,padding=False))
    assert len(B)==1
    assert g.bitcnt==32
    assert g.padcnt==0
    B = list(g.iterblocks(b'A'*8,padding=False))
    assert len(B)==2
    assert g.bitcnt==96
    assert g.padcnt==0
    B = list(g.new.iterblocks(b'A'*8,padding=False))
    assert len(B)==2
    assert g.bitcnt==64
    assert g.padcnt==0
    B = list(g.iterblocks(b'A'*8,bitlen=32,padding=False))
    assert len(B)==1
    assert g.bitcnt==96
    assert g.padcnt==0

def test_blockiterator_003():
    g = blockiterator(32)
    B = list(g.iterblocks(b'A'*9,bitlen=64,padding=False))
    assert len(B)==2
    assert g.bitcnt==64
    assert g.padcnt==0
    with pytest.raises(PaddingError) as exc:
        B = list(g.iterblocks(b'A'*9,padding=False))
    assert 'input not a multiple of block size' == exc.value.value
    B = list(g.iterblocks(b'A'*12,bitlen=64,padding=False))
    assert len(B)==2
    assert g.bitcnt == 128
    with pytest.raises(PaddingError) as exc:
        B = list(g.iterblocks(b'A'*7,bitlen=64,padding=False))
    assert exc.value.value == 'input bitlen mismatch'

def test_nopadding_001():
    pad = nopadding(16)
    c = 0
    for b in pad.iterblocks(b'A'*20):
        if not pad.padflag: assert len(b)==2
        c += len(b)
        assert pad.bitcnt==c*8
    assert pad.padflag
    assert pad.padcnt==0
    assert pad.bitcnt==20*8
    with pytest.raises(PaddingError) as exc:
        next(pad.iterblocks(b'A'))
    assert exc.value.value=='padding already added'

def test_nopadding_002():
    pad = nopadding(32)
    for b in pad.iterblocks(b'A'*5): pass
    assert len(b)==1
    assert pad.padcnt==0
    assert pad.bitcnt==40

def test_Nullpadding_001():
    pad = Nullpadding(64)
    for b in pad.iterblocks(b'A'*20):
        assert len(b)==8
    assert pad.padflag
    assert pad.padcnt/8 == 4
    assert b[-4:]==b'\0'*4
    assert pad.remove(b)==b'AAAA'

def test_Nullpadding_002():
    pad = Nullpadding(64)
    for b in pad.iterblocks(b'A'*25,bitlen=192):
        assert len(b)==8
    assert pad.padflag
    assert pad.padcnt == 0
    assert pad.remove(b)==b

def test_Nullpadding_003():
    pad = Nullpadding(16)
    c=0
    for b in pad.iterblocks(b'A'):
        assert len(b)==2
        c+=1
    assert c==1
    assert pad.bitcnt==8
    assert pad.padflag
    assert pad.padcnt == 8
    assert b[-1:]==b'\0'

def test_bitpadding_001():
    pad = bitpadding(64)
    for b in pad.iterblocks(b'A'*20):
        assert len(b)==8
    assert pad.padflag
    assert pad.padcnt/8 == 4
    assert b[-4:-3]==b'\x80'
    assert pad.remove(b)==b'AAAA'

def test_bitpadding_002():
    pad = bitpadding(64)
    for b in pad.iterblocks(b'A'*25,bitlen=192):
        assert len(b)==8
    assert pad.padflag
    assert pad.padcnt == 64
    assert pad.remove(b)==b''

def test_bitpadding_003():
    pad = bitpadding(64)
    for b in pad.iterblocks(b'A'*8,bitlen=63):
        assert len(b)==8
    assert pad.padflag
    assert pad.bitcnt==63
    assert pad.padcnt == 1
    assert pad.remove(b)[-1]&0xfe == ord(b'A')&0xfe

def test_pkcs7_001():
    pad = pkcs7(64)
    B = list(pad.iterblocks(b'A'*17))
    assert len(B)==3
    assert pad.padflag
    assert pad.bitcnt==17*8
    assert pad.padcnt==56
    assert B[-1][-1:]==b'\x07'
    assert pad.remove(B[-1])==b'A'
