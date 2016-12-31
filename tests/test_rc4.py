import pytest
import codecs
from crysp.rc4 import *

def test_rc4_001():
    k = b'Key'
    assert RC4(k).enc(b'Plaintext') == codecs.decode(b'BBF316E8D940AF0AD3','hex')

def test_rc4_002():
    k = b'Secret'
    assert RC4(k).enc(b'Attack at dawn') == codecs.decode(b'45A01F645FC35B383552544B9BF5','hex')

