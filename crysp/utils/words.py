#!/usr/bin/env python
from __future__ import print_function
# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license

import matplotlib
matplotlib.use('GTKCairo',warn=False)
from matplotlib import pyplot

import re

def hist(files):
    W = dict()
    N = 0
    for fname in files:
        try:
            f = open(fname)
        except:
            print('error opening file %s'%fname)
            continue
        print('processing file %s ...'%fname,end='')
        for l in f.readlines():
            s = l.decode('latin1')
            for w in re.findall('\w+',s,flags=re.I|re.U):
                N += 1
                try:
                    W[w] += 1
                except KeyError:
                    W[w] = 1
        print('done.')
    for v in W.itervalues():
        v = v*1./N
    return W

def histplot(W,title='',color=None,edgecolor=None):
    if not color: color='red'
    if not edgecolor: edgecolor='yellow'
    n = len(W)
    K = sorted(W,key=W.get,reverse=True)
    pyplot.bar(left=range(n),height=[W[k] for k in K],color=color,edgecolor=edgecolor)
    pyplot.xlabel('words')
    pyplot.ylabel('%')
    ax = pyplot.gca()
    ax.set_xlim(0,n)
    labels = ax.set_xticklabels(K)

if __name__=='__main__':
    import sys
    targets = []
    Refs = sys.argv[1:]

    if '-c' in Refs:
        assert Refs.count('-c')==1
        i = Refs.index('-c')
        assert len(Refs)>(i+1)
        targets.extend(Refs[i+1:])
        Refs = Refs[:i]

    Wref = hist(Refs)

    #pyplot.figure(1)

    #if len(targets)>0:
    #    W = hist(targets)
    #    pyplot.subplot(211)
    #    histplot(W,'target:',color='red',edgecolor='yellow')
    #    pyplot.subplot(212)
    #histplot(Wref,title='reference:',color='blue',edgecolor='white')
    #pyplot.show()
