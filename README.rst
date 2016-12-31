=====
Crysp
=====
----------------------
Crypto Stuff in Python
----------------------

.. image:: https://travis-ci.org/bdcht/crysp.svg?branch=master
    :target: https://travis-ci.org/bdcht/crysp

+-----------+-----------------------------------+
| Status:   | Under Development                 |
+-----------+-----------------------------------+
| Location: | https://github.com/bdcht/crysp    |
+-----------+-----------------------------------+
| Version:  | 0.9                               |
+-----------+-----------------------------------+

Description
===========

crysp is a python package with some of my crypto-related facilities.

Install
=======

crysp/utils suggests the following python packages:

- matplotlib_, for displaying histograms.
- grandalf_, in utils/freq2.py.

Overview
========

*bits.py*
---------

Contains the bitvector/bitstream manipulation methods.
This module defines the classes:

- Bits

Bits.
~~~~~

A Bits object is defined by a long ival, a size field and a mask.
It can be created from either:

- an int or long,
- a list of bit values ([0,0,1,...,0,1,1]) with LSB first,
- a string, also with LSB first,
- or another Bits instance.

A Bits object ival holds the list of bits encoded in base10 with bit0 being
the LSB of ival.
When created from an integer value, this value simply defines the ival,
and the size/mask is computed automatically.
When created from a bit list the list defines bits LSB to MSB.
When created from a string, the string is parsed as a stream of bits :
the bit with index 0 (LSB of ival) is the MSB of the first char.
It can be tricky to get used to this initialisation convention, especially
looking at /b1/ and /b3/ in the following example:
Optionnally, the bytestring can be decoded as a little-endian arbitrary long
integer by using parameter bitorder=1:

.. sourcecode:: python

   >>> b1 = Bits(10)
   >>> b2 = Bits([0,1,0,1])
   >>> b3 = Bits('\x50',size=4)
   >>> b4 = Bits('\x0a',size=4,bitorder=1)
   >>> b1==b2==b3==b4
   True


*poly.py*
---------

Contains the bytevector/bytestream manipulation methods.
This module defines the classes:

- Poly

Poly.
~~~~~

This class API is very similar to Bits, but extends to polynomials in arbitrary rings.
It allows for example to operate on bytes (ring=256) rather than bits.

*crc.py*
--------

Contains generic CRC and CRC32 manipulation algorithms.
This module defines the functions:

- crc_table, crc_back_table
- crc
- crc_back_pos
- crc32
- crc32_back_pos
- crc32_fix, crc32_fix_pos

Most functions are self-explanatory ;)

*des.py*
--------

*wb.py*
-------

*keccak.py*
-----------

Contains the Keccak class which provides a full implementation of the Keccak sponge functions family.
This module also defines the 4 SHA-3 instances: sha3_224, sha3_256, sha3_384, sha3_512.
See tests/test-keccak.py for examples.

utils/
------

Contains some grandpa crypto utilities that are still useful sometimes...

.. _matplotlib: http://matplotlib.sourceforge.net
.. _grandalf: https://github.com/bdcht/grandalf
