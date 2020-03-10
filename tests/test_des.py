import pytest
import codecs
from crysp.bits import Bits
from crysp.des import TDEA,DES
from crysp.wb import table_rKT,table_M1,table_M2,table_M3,WhiteDES
from crysp.mode import ECB,CBC

def test_des_wb():
    K = codecs.decode(b"0123456789ABCDEF",'hex')
    bK = Bits(K,64)
    b1 = b"Now is t"
    b2 = b"he time "
    b3 = b"for"+b"\5"*5
    KT = []
    for r in range(16):
        s,t = table_rKT(r,bK)
        KT.append(t)
    E  = DES(K)
    WT = ECB(WhiteDES(KT,table_M1(),table_M2()[0],table_M3()))
    c = WT.enc(b"Now is the time for")
    assert c == E.enc(b1)+E.enc(b2)+E.enc(b3)

def test_3des():
    E = CBC(TDEA(b'12345678abcdabcd'), IV=b'tototiti')
    c=b'\xd7+\x0c\xads\x8aX\xe3\xa5;1\xd0\xd2g^bS\x11\xd0\xd6\xf6\xcfA\xc8'
    assert E.enc(b"CBC 3DES testing")[8:]==c


