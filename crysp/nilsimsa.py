from crysp.bits import *

# from nilsimsa 0.2.4 archive:
# Nilsimsa uses eight sets of character separations (character, character, etc.)
# and takes the three characters and performs a computation on them: 
# (((tran[((a)+(n))&255]^tran[(b)]*((n)+(n)+1))+tran[(c)^tran[n]])&255), 
# where a, b, and c are the characters, n is 0-7 indicating which separation, 
# and tran is a permutation of [0-255].
# The result is a byte, and nilsimsa throws all these bytes from all eight
# separations into one histogram and encodes the histogram.

class Nilsimsa(object):
    def __init__(self,target=None):
        if target is None: target=53
        self.tran = self.maketran(target)
        self.reset()

    def reset(self):
        self.count = 0
        self.dacc = [0]*256
        self.seen = [None]*4

    def update(self,data):
        if isinstance(data,str): data = map(ord,data)
        for b in data:
            w3,w2,w1,w0 = self.seen[-4:]
            self.count += 1
            if w1!=None:
                self.dacc[self.tran3(b,w0,w1,0)] += 1
            if w2!=None:
                self.dacc[self.tran3(b,w0,w2,1)] += 1
                self.dacc[self.tran3(b,w1,w2,2)] += 1
            if w3!=None:
                self.dacc[self.tran3(b,w0,w3,3)] += 1
                self.dacc[self.tran3(b,w1,w3,4)] += 1
                self.dacc[self.tran3(b,w2,w3,5)] += 1
                #
                self.dacc[self.tran3(w3,w0,b,6)] += 1
                self.dacc[self.tran3(w3,w2,b,7)] += 1
            self.seen.append(b)
        return self

    def digest(self):
        total = 0
        if self.count == 3:
            total = 1
        elif self.count == 4:
            total = 4
        elif self.count>4:
            total = 8*self.count - 28
        thres = total//256
        code = [0]*32
        for i in range(256):
            if self.dacc[i]>thres:
                code[i>>3] += 1<<(i&7)
        self.reset()
        return bytes(bytearray(code[::-1]))

    def __call__(self,data):
        return self.update(data).digest()

    def tran3(self,a,b,c,n):
        return (((self.tran[(a+n)&255]^self.tran[b]*(n+n+1))+self.tran[c^self.tran[n]])&255)

    def maketran(self,target):
        T = [0]*256
        j=0
        for i in range(256):
            j = (j*target+1)&255
            j += j
            if j>255: j-=255
            k = 0
            while k<i:
                if T[k]==j:
                    j = (j+1)&255
                    k = 0
                k+=1
            T[i] = j
        return T

def distance(h1,h2):
    return Bits(h1).hd(h2)
