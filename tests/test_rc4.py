import pytest

from crysp.rc4 import *

def test_rc4_001():
    k = 'Key'
    assert RC4(k).enc('Plaintext') == 'BBF316E8D940AF0AD3'.decode('hex')

def test_rc4_002():
    k = 'Secret'
    assert RC4(k).enc('Attack at dawn') == '45A01F645FC35B383552544B9BF5'.decode('hex')

