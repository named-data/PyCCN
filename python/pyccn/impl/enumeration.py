#
# Copyright (c) 2012, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#

import pyccn
from pyccn.impl import ccnb

def ccnb_enumerate(names):
	out = bytearray()

	for name in names:
		out += ccnb.dtag(ccnb.DTAG_LINK, name.get_ccnb())

	return ccnb.dtag(ccnb.DTAG_COLLECTION, out)
