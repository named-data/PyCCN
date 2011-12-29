#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#             Jeff Burke <jburke@ucla.edu>
#

__all__ = ['CCN', 'Closure', 'ContentObject', 'Interest', 'Key', 'Name']

import sys as _sys

try:
	from CCN import *
	from Closure import *
	from ContentObject import *
	from Interest import *
	from Key import *
	from Name import *
except ImportError:
	del _sys.modules[__name__]
	raise

#def name_compatibility():
#	global _name_immutable
#
#	_name_immutable = 1

