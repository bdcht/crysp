class Substitution(object):
    def __init__(self,data=None):
        self.key = [b'-']*256
        self.data = data
    def setkey(self,c,v):
        self.key[ord(c)]=v
    def getkey(self,c):
        return chr(self.key.index(c))
    def __call__(self,data=None):
        if data is None:
            data = self.data
        if data is None:
            return
        kstr=b''.join(self.key)
        return data.translate(kstr)

class Transposition(object):
    pass
