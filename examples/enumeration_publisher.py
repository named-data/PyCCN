#! /usr/bin/env python

#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#

import sys
import pyccn
from pyccn.impl.enumeration import ccnb_enumerate
from pyccn.impl.segmenting import segmenter, Wrapper

def generate_names():
	names = ["/Hello", "/World", "/This", "/is", "/an", "/enumeration", "/example"]
	return map(lambda x: pyccn.Name(x), names)

def main(args):
	if len(sys.argv) != 2:
		usage()

	name = pyccn.Name(sys.argv[1])
	data = ccnb_enumerate(generate_names())

	key = pyccn.CCN.getDefaultKey()
	name = name.append('\xc1.E.be').appendKeyID(key).appendVersion()

	wrapper = Wrapper(name, key)
	sgmtr = segmenter(data, wrapper)

	handle = pyccn.CCN()
	for seg in sgmtr:
		handle.put(seg)

	return 0

def usage():
	print("Usage: %s <uri>" % sys.argv[0])
	sys.exit(1)

if __name__ == '__main__':
	sys.exit(main(sys.argv))
