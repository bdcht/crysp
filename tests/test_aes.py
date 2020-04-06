import pytest
import codecs
from crysp.aes import *

aes_vectors = [('2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c' ,
                '32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34' ,
                '39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32'),
               ('2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c' ,
                '32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34' ,
                '39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32'),
              ]

def test_aes_gmul():
    assert gmul(0x57,0x83) == 0xc1
    assert gmul(0x57,0x13) == 0xfe
    assert gmul(0x57,0x08) == 0x8e
    assert gmul(0,3) == 0

def test_aes_keyschedule():
    k,m,c = (codecs.decode(s.replace(' ',''),'hex') for s in aes_vectors[0])
    E = AES(k)
    assert E.Nb==4
    assert E.Nk==4
    assert E.Nr==10
    E.keyschedule()
    w = E._AES__w
    assert len(w)==E.Nb*(E.Nr+1)
    assert pack(w[4])  == b'\xa0\xfa\xfe\x17'
    assert pack(w[19]) == b'\xdb\x0b\xad\x00'
    assert pack(w[43]) == b'\xb6c\x0c\xa6'

@pytest.mark.parametrize('k,m,c',aes_vectors)
def test_aes_vectors(k,m,c):
    k,m,c = (codecs.decode(s.replace(' ',''),'hex') for s in (k,m,c))
    E = AES(k)
    assert E.enc(m) == c
    assert E.dec(c) == m

def test_aes_128_random():
    import random
    E = AES(pack(Bits(random.getrandbits(128),128)))
    assert E.Nk==4
    assert E.Nb==4
    assert E.Nr==10
    m = pack(Bits(random.getrandbits(128),128))
    assert E.dec(E.enc(m)) == m

def test_aes_192_random():
    import random
    E = AES(pack(Bits(random.getrandbits(192),192)))
    assert E.Nk==6
    assert E.Nb==4
    assert E.Nr==12
    m = pack(Bits(random.getrandbits(128)))
    assert E.dec(E.enc(m)) == m

def test_aes_256_random():
    import random
    E = AES(pack(Bits(random.getrandbits(256),256)))
    assert E.Nk==8
    assert E.Nb==4
    assert E.Nr==14
    m = pack(Bits(random.getrandbits(128)))
    assert E.dec(E.enc(m)) == m

def test_aes_ctr():
    from crysp.mode import DefaultCounter,CTR
    K = codecs.decode("2b7e151628aed2a6abf7158809cf4f3c","hex")
    iv = codecs.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff","hex")

    m1 = codecs.decode("6bc1bee22e409f96e93d7e117393172a","hex")
    m2 = codecs.decode("ae2d8a571e03ac9c9eb76fac45af8e51","hex")
    m3 = codecs.decode("30c81c46a35ce411e5fbc1191a0a","hex")

    E = CTR(AES(K),iv)

    c1 = E.enc(m1)
    assert c1.hex() == "874d6191b620e3261bef6864990db6ce"
    c12 = E.enc(m1+m2)
    assert c12.hex() == c1.hex()+"9806f66b7970fdff8617187bb9fffdff"
    c123 = E.enc(m1+m2+m3)
    assert c123.hex() == c12.hex()+"5ae4df3edbd5d35e5b4f09020db0"
