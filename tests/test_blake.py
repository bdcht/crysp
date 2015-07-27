import pytest

from crysp.blake import *

m1 = '\0'
m2 = "\0"*72
vectors_blake256=[(m1,"0CE8D4EF4DD7CD8D62DFDED9D4EDB0A774AE6A41929A74DA23109E8F11139C87"),
                  (m2,"D419BAD32D504FB7D44D460C42C5593FE544FA4C135DEC31E21BD9ABDCC22D41"),
                 ]
vectors_blake224=[(m1,"4504CB0314FB2A4F7A692E696E487912FE3F2468FE312C73A5278EC5"),
                  (m2,"F5AA00DD1CB847E3140372AF7B5C46B4888D82C8C0A917913CFB5D04"),
                 ]
vectors_blake512=[(m1   ,"97961587F6D970FABA6D2478045DE6D1FABD09B61AE50932054D52BC29D31BE4FF9102B9F69E2BBDB83BE13D4B9C06091E5FA0B48BD081B634058BE0EC49BEB3"),
                  (m2+m2,"313717D608E9CF758DCB1EB0F0C3CF9FC150B2D500FB33F51C52AFC99D358A2F1374B8A38BBA7974E7F6EF79CAB16F22CE1E649D6E01AD9589C213045D545DDE"),
                   ]
vectors_blake384=[(m1   ,"10281F67E135E90AE8E882251A355510A719367AD70227B137343E1BC122015C29391E8545B5272D13A7C2879DA3D807"),
                  (m2+m2,"0B9845DD429566CDAB772BA195D271EFFE2D0211F16991D766BA749447C5CDE569780B2DAA66C4B224A2EC2E5D09174C"),
                 ]

@pytest.mark.parametrize('m,h',vectors_blake256)
def test_blake256(m,h):
    assert blake256(m).encode('hex')==h.lower()
@pytest.mark.parametrize('m,h',vectors_blake224)
def test_blake224(m,h):
    assert blake224(m).encode('hex')==h.lower()
@pytest.mark.parametrize('m,h',vectors_blake512)
def test_blake512(m,h):
    assert blake512(m).encode('hex')==h.lower()
@pytest.mark.parametrize('m,h',vectors_blake384)
def test_blake384(m,h):
    assert blake384(m).encode('hex')==h.lower()
