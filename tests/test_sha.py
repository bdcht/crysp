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

@pytest.mark.parametrize('m,h',[('abc','0164b8a914cd2a5e74c4f7ff082c4d97f1edf880')])
def test_sha1_003(m,h):
    sha0 = SHA1(version=0)
    assert sha0(m).encode('hex') == h

vectors_sha256 = [(""    ,"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
                  ("a"   ,"CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB"),
                  ("abc" ,"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"),
                 ]
@pytest.mark.parametrize('m,h',vectors_sha256)
def test_sha2_001(m,h):
    sha256 = SHA2(256)
    assert sha256(m).encode('hex') == h.lower()

vectors_sha224 = [(""    ,"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
                  ("abc" ,"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
                 ]
@pytest.mark.parametrize('m,h',vectors_sha224)
def test_sha2_002(m,h):
    sha224 = SHA2(224)
    assert sha224(m).encode('hex') == h

vectors_sha384 = [(""    ,"38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"),
                  ("a"   ,"54A59B9F22B0B80880D8427E548B7C23ABD873486E1F035DCE9CD697E85175033CAA88E6D57BC35EFAE0B5AFD3145F31"),
                  ("abc" ,"CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7"),
                 ]
@pytest.mark.parametrize('m,h',vectors_sha384)
def test_sha2_003(m,h):
    sha384 = SHA2(384)
    assert sha384(m).encode('hex') == h.lower()

vectors_sha512 = [(""    ,"CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"),
                  ("a"   ,"1F40FC92DA241694750979EE6CF582F2D5D7D28E18335DE05ABC54D0560E0F5302860C652BF08D560252AA5E74210546F369FBBBCE8C12CFC7957B2652FE9A75"),
                  ("abc" ,"DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"),
                 ]
@pytest.mark.parametrize('m,h',vectors_sha512)
def test_sha2_004(m,h):
    sha512 = SHA2(512)
    assert sha512(m).encode('hex') == h.lower()

