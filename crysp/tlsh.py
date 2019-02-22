from crysp.bits import *
from functools import reduce

# ref: TLSH - A Locality Sensitive Hash, J. Oliver, C. Cheng, Y. Chen, TrendMicro, 2014.

PEARSON_T = [1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
             14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
             110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
             25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
             97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
             174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
             132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
             119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
             138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
             170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
             125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
             118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
             27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
             233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
             140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
             51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209]

class TLSH(object):
    def __init__(self,buckets,wndsize=5,chklen=1):
        assert buckets in (256,128,48)
        assert wndsize in (4,5,6,7,8)
        assert chklen in  (1,3)
        self.bktlen = buckets
        self.codesize = buckets//4
        self.wnd_size = wndsize
        self.chklen = chklen
        self.MIN_DATA_LENGTH = (50,256)
        self.reset()

    def reset(self):
        self.a_bucket = None
        self.slide_window = bytearray(self.wnd_size)
        self.data_len = 0
        # lsh_bin:
        self.checksum = bytearray(self.chklen)
        self.Lvalue = 0
        self.q1_ratio = None
        self.q2_ratio = None
        self.tmp_code = bytearray(self.codesize)
        self.lsh_code = None
        self.lsh_code_valid = False

    def update(self,data):
        if isinstance(data,str): data = map(ord,data)
        if self.lsh_code_valid:
            self.reset()
        # step 1: process data in buckets:
        self.a_bucket = [0]*256
        wsz = self.wnd_size
        for ew in range(wsz,len(data)+1):
            d0,d1,c = data[ew-1],data[ew-2],self.checksum[0]
            self.checksum[0] = self.b_mapping((0,d0,d1,c))
            for k in range(1,self.chklen):
                s,c = self.checksum[k-1],self.checksum[k]
                self.checksum[k] = self.b_mapping((s,d0,d1,c))
            sw = ew-wsz
            for c in self.triplet(data[sw:ew]):
                bi = self.b_mapping(c)
                self.a_bucket[bi] += 1
        self.data_len += len(data)
        return self

    def final(self,data,force=False):
        if not self.lsh_code_valid:
            if data: self.update(data)
            l = self.data_len
            m1,m2 = self.MIN_DATA_LENGTH
            if (l<m1) or (not force and (l<m2)):
                return None
            q1,q2,q3 = self.find_quartiles()
            l = self.bktlen
            nonzero = len(list(filter(None,self.a_bucket[:l])))
            if (l==48 and nonzero<18) or (nonzero<= l//2):
                return None
            for bi in range(l):
                bv = self.a_bucket[bi]
                i,j = divmod(bi,4)
                if   q3<bv: self.tmp_code[i] += 3<<(j*2)
                elif q2<bv: self.tmp_code[i] += 2<<(j*2)
                elif q1<bv: self.tmp_code[i] += 1<<(j*2)
            self.Lvalue = self.l_capturing()
            self.q1_ratio = int((q1*100./q3))%16
            self.q2_ratio = int((q2*100./q3))%16
            self.lsh_code_valid = True
        return self

    def __call__(self,data,force=False):
        self.reset()
        self.final(data,force).digest()
        return self.lsh_code

    def digest(self):
        if self.lsh_code_valid:
            swp8 = (lambda x: (x&0xf)<<4 | x>>4)
            checksum = bytearray([swp8(x) for x in self.checksum])
            lvalue   = bytearray([swp8(self.Lvalue)])
            qb       = bytearray([(self.q1_ratio<<4)|self.q2_ratio])
            code     = self.tmp_code[::-1]
            self.lsh_code = bytes(checksum+lvalue+qb+code)
        return self

    def from_hash(self,data):
        swp8 = (lambda x: (x&0xf)<<4 | x>>4)
        if isinstance(data,str): data = map(ord,data)
        data = list(data)
        self.reset()
        l = self.chklen
        ck,rest = data[:l],data[l:]
        self.checksum = bytearray([swp8(x) for x in ck])
        self.Lvalue   = swp8(rest.pop(0))
        qb = rest.pop(0)
        self.q1_ratio = qb>>4
        self.q2_ratio = qb&0xf
        self.tmp_code = bytearray(rest[::-1])
        self.lsh_code_valid = (len(rest)==self.codesize)
        self.digest()
        assert self.lsh_code == bytearray(data)
        return self

    def triplet(self,data):
        try:
            # wnd_size >=4:
            yield (2 ,data[-1],data[-2],data[-3])
            yield (3 ,data[-1],data[-2],data[-4])
            yield (5 ,data[-1],data[-3],data[-4])
            # wnd_size >=5
            yield (7 ,data[-1],data[-3],data[-5])
            yield (11,data[-1],data[-2],data[-5])
            yield (13,data[-1],data[-4],data[-5])
            # wnd_size >=6
            yield (17,data[-1],data[-2],data[-6])
            yield (19,data[-1],data[-3],data[-6])
            yield (23,data[-1],data[-4],data[-6])
            yield (29,data[-1],data[-5],data[-6])
            # wnd_size >=7
            yield (31,data[-1],data[-2],data[-7])
            yield (37,data[-1],data[-3],data[-7])
            yield (41,data[-1],data[-4],data[-7])
            yield (43,data[-1],data[-5],data[-7])
            yield (47,data[-1],data[-6],data[-7])
            # wnd_size >=8
            yield (53,data[-1],data[-2],data[-8])
            yield (59,data[-1],data[-3],data[-8])
            yield (61,data[-1],data[-4],data[-8])
            yield (67,data[-1],data[-5],data[-8])
            yield (71,data[-1],data[-6],data[-8])
            yield (73,data[-1],data[-7],data[-8])
        except IndexError:
                return

    def b_mapping(self,c):
        return reduce(lambda x,y:PEARSON_T[x^y],c,0)

    def find_quartiles(self):
        l = self.codesize
        p1  = l-1
        p2  = p1+l
        p3  = p2+l
        end = p3+l
        bkt = sorted(self.a_bucket[:self.bktlen])
        return float(bkt[p1]),float(bkt[p2]),float(bkt[p3])

    def l_capturing(self):
        from math import floor,log
        l = self.data_len
        if l<=656:
            i = floor(log(l,1.5))
        elif l<=3199:
            i = floor(log(l,1.3)-8.72777)
        else:
            i = floor(log(l,1.1)-62.5472)
        return int(i)&0xff

    def distance_to(self,h):
        return distance(self,h)

def distance(h0,h1,lvalue=True):
    if isinstance(h0,bytes):
        l = len(h0)
        if   l>66: th0 = TLSH(256,chklen=l-66).from_hash(h0)
        elif l>34: th0 = TLSH(128,chklen=l-34).from_hash(h0)
        elif l>14: th0 = TLSH(48 ,chklen=l-14).from_hash(h0)
        else: th0 = None
    else:
        th0 = h0
    if isinstance(h1,bytes):
        l = len(h1)
        if   l>66: th1 = TLSH(256,chklen=l-66).from_hash(h1)
        elif l>34: th1 = TLSH(128,chklen=l-34).from_hash(h1)
        elif l>14: th1 = TLSH(48 ,chklen=l-14).from_hash(h1)
        else: th1 = None
    else:
        th1 = h1
    if th0 and th1:
        assert th0.chklen == th1.chklen
        def diffmod(x,y,n=256):
            d0 = abs(x%n - y%n)
            d1 = n-d0
            return min(d0,d1)
        diff = 0
        # checksum compare:
        if th1.checksum != th0.checksum: diff += 1
        if lvalue:
        # Lvalue compare:
            d = diffmod(th1.Lvalue,th0.Lvalue)
            diff += d if d<=1 else d*12
        # Q ratio compare:
        d = diffmod(th1.q1_ratio,th0.q1_ratio,16)
        diff += d if d<=1 else (d-1)*12
        d = diffmod(th1.q2_ratio,th0.q2_ratio,16)
        diff += d if d<=1 else (d-1)*12
        # code compare:
        for tx,ty in zip(th1.tmp_code,th0.tmp_code):
            for t in range(4):
                tx,d0 = divmod(tx,4)
                ty,d1 = divmod(ty,4)
                d = abs(d0 - d1)
                diff += d
                if d==3: diff += d
        return diff

tlsh = TLSH(128)
