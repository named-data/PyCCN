#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#             Jeff Burke <jburke@ucla.edu>
#

__all__ = ['Face', 'Closure', 'ContentObject', 'Interest', 'Key', 'Name']

import sys as _sys

try:
	from ndn.Face import *
	from ndn.Closure import *
	from ndn.ContentObject import *
	from ndn.Interest import *
	from ndn.Key import *
	from ndn.Name import *
	from ndn import NameCrypto
        from ndn.LocalPrefixDiscovery import *

except ImportError:
	del _sys.modules[__name__]
	raise

def name_compatibility():
	global _name_immutable

	_name_immutable = 1

