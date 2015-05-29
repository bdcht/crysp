from crysp.serpent import *

S = Serpent(K)

inputstr = "000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f"

#Serpent/CBC/PKCS7Padding :
output1 = "f8940ca31aba8ce1e0693b1ae0b1e08daef6de03c80f019774280052f824ac44540bb8dd74dfad47f83f9c7ec268ca68"
#Serpent/CBC/WithCTS",
output2 = "aef6de03c80f019774280052f824ac44f8940ca31aba8ce1e0693b1ae0b1e08d"

