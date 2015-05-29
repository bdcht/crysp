# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

# recursive iterator over the group of (n-k)! permutations
# of the last n-k elements of list l (k-deep permutations).
# k=0 returns ALL n! permutations
def permutk(l,k):
    assert k>=0
    if k>=len(l):
        yield l[:]
    for i in range(k,len(l)):
        tmp = l[i]
        for j in range(i,k,-1):
            l[j] = l[j-1]
        l[k] = tmp
        for p in permutk(l,k+1): yield p
        for j in range(k,i): l[j] = l[j+1]
        l[i] = tmp

# inplace permute list l to "next" permutation
# according to the natural order induced by
# comparisons of its elements.
def nextperm(l):
    k = len(l)-2
    while (k>=0 and l[k]>l[k+1]): k -= 1
    lpos = k+1
    rpos=len(l)-1
    while lpos<rpos:
        l[lpos],l[rpos] = l[rpos],l[lpos]
        lpos += 1
        rpos -= 1
    if k==-1:
        return l
    i = k+1
    while (l[i]<l[k]): i+=1
    l[i],l[k] = l[k],l[i]
    return l

# recursive iterator providing k-deep combinations of
# p elements of list l. The combinations order is induced
# by indices of the elements in l.
def combink(l,p,k):
    assert k>=0
    n = len(l)
    assert 0<p<=n
    # create internal "static" variable:
    if not hasattr(combink,'r'):
        combink.r = range(n)+[-1]
    if k<p:
        #print '\t'*k + "k=%d, loop:[%d,%d]"%(k,combink.r[k-1]+1,n-p+k+1)
        for i in range(combink.r[k-1]+1, n-p+k+1):
            combink.r[k]=i
            for x in combink(l,p,k+1):
                yield x
        # if recursion is back to initial call
        # then cleanup internal static variable:
        if k==0: del combink.r
    else:
        #print '\t'*k + 'k=%d, r='%k,combink.r,'yield =>',
        yield [l[i] for i in combink.r[:p]]


