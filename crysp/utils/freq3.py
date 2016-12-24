#!/usr/bin/env python
# This code is part of crysp
# Copyright (C) 2009-2014 Axel Tillequin (bdcht3@gmail.com) 
# published under GPLv2 license
from __future__ import print_function

import matplotlib
matplotlib.use('GTKCairo',warn=False)
from matplotlib import pyplot

def hist(files):
    H = {}
    N = 0
    for fname in files:
        try:
            f = open(fname)
        except:
            print('error opening file %s'%fname)
            continue
        print('processing file %s ...'%fname,end='')
        s = map(ord,f.read())
        n = len(s)-2
        N += n
        for i in xrange(n):
            try:
                H['%c%c%c'%(s[i],s[i+1],s[i+2])] += 1
            except KeyError:
                H['%c%c%c'%(s[i],s[i+1],s[i+2])] = 1
        print('done.')
    IC = 0
    for k in H.iterkeys():
        IC += H[k]*(H[k]-1)
        H[k] = (1.0*H[k])/N
    IC = IC/(N*(N-1.0))
    return (H,IC,N)

def histplot(H,IC,thres=0.0025,title='',color=None,edgecolor=None):
    if not color: color='red'
    if not edgecolor: edgecolor='yellow'
    ex=[]
    for k,v in H.iteritems():
        if v>thres: ex.append(k)
    pyplot.bar(left=range(len(ex)),height=[H[t] for t in ex],color=color,edgecolor=edgecolor)
    pyplot.title('%s 3-symbols histogram (IC=%f, thres=%f)'%(title,IC,thres))
    pyplot.xlabel('3-grams')
    ax=pyplot.gca()
    ax.set_xlim(0,len(ex))
    ax.set_xticks(range(len(ex)))
    ax.set_xticklabels(["'%s'"%x.decode('latin-1') for x in ex],fontsize='xx-small',ha='left')
    pyplot.ylabel('%')

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
        histplot(H,IC,title='target:',color='red',edgecolor='yellow')
        pyplot.subplot(212)
    histplot(Href,ICref,title='reference:',color='blue',edgecolor='white')
    pyplot.show()
