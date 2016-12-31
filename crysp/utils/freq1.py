#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license
from __future__ import print_function

import matplotlib
matplotlib.use('GTKCairo',warn=False)
from matplotlib import pyplot

def hist(files):
    H = dict(zip( range(256), [0]*256 ))
    N = 0
    for fname in files:
        try:
            f = open(fname)
        except:
            print('error opening file %s'%fname)
            continue
        print('processing file %s ...'%fname,end='')
        s = map(ord,f.read())
        N += len(s)
        for c in s:
            H[c] += 1
        print('done.')
    IC = 0
    for c in range(256):
        IC += H[c]*(H[c]-1)
        H[c] = (1.0*H[c])/N
    IC = IC/(N*(N-1.0))
    return (H,IC,N)

def histplot(H,IC,title='',color=None,edgecolor=None):
    if not color: color='red'
    if not edgecolor: edgecolor='yellow'
    pyplot.bar(left=H.keys(),height=H.values(),color=color,edgecolor=edgecolor)
    pyplot.title('%s histogram (IC=%f)'%(title,IC))
    pyplot.xlabel('symbols')
    pyplot.ylabel('%')
    ax = pyplot.gca()
    ax.set_xlim(0,256)
    ax.set_xticks((10,32,49,65,97,231))
    labels = ax.set_xticklabels(('10:\\n','32:sp','49:num','65:A-Z','97:a-z','231:çéèêë'))

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

    Href,ICref,Nref = hist(Refs)

    pyplot.figure(1)

    if len(targets)>0:
        H,IC,N = hist(targets)
        pyplot.subplot(211)
        histplot(H,IC,'target:',color='red',edgecolor='yellow')
        pyplot.subplot(212)
    histplot(Href,ICref,title='reference:',color='blue',edgecolor='white')
    pyplot.show()
