import pytest
import codecs
from crysp.rc4 import *

def test_rc4_001():
    k = b'Key'
    X = RC4(k)
    assert X.S.ival[0:4] == [75, 51, 132, 157]
    assert X.keystream(16).ival == [235, 159, 119, 129, 183, 52, 202, 114, 167, 25, 74, 40, 103, 182, 66, 149]
    assert RC4(k).enc(b'Plaintext') == codecs.decode(b'BBF316E8D940AF0AD3','hex')

def test_rc4_002():
    k = b'Secret'
    assert RC4(k).enc(b'Attack at dawn') == codecs.decode(b'45A01F645FC35B383552544B9BF5','hex')

