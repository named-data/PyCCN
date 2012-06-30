import pyccn
from pyccn.impl import ccnb

def enumerate(names):
	out = bytearray()
	for name in names:
		out += ccnb.dtag(ccnb.DTAG_LINK, name.get_ccnb())

	return ccnb.dtag(ccnb.DTAG_COLLECTION, out)
