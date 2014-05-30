# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license

# for a list l of couples (object,weight), return a
# list of unique couples with sum of weights equal s. 
# result is not "optimal" by any means, it is just the
# first recursive solution encountered.
def exactsum(l,s,i=0,r=[]):
    n = len(l)
    if s==0: return True
    if s<0 or i==n: return False
    if exactsum(l,s-l[i][1],i+1):
        r.append(l[i])
        return True if i else r
    else:
        return exactsum(l,s,i+1)

# a simple version of dynamic programming method
# to find a minimal-length list of couples from l
# with sum of weights equal to s.
def dynprog(l,s):
    n = len(l)
    p = {}
    p[0] = [0]
    for x in range(1,s+1):
        m = None
        for i in range(n):
            u = x-l[i][1]
            if (u>=0 and (u in p) and (p[u][0]<m or m==None)):
                    m = p[u][0]
                    im = i
        if m!=None:
            p[x] = [m+1]
            src  = p[x-l[im][1]]
            for j in range(1,m+1): p[x].append(src[j])
            p[x].append(l[im])
        else:
            if x in p:
                del p[x]
    try:
        return p[s][1:]
    except KeyError:
        return None
