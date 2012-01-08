#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#             Jeff Burke <jburke@ucla.edu>
#

from . import _pyccn

# Iterate through components and check types when serializing.
# Serialize strings without the trailing 0

# Expose the container types?
# Allow init with a uri or a string?

# Byte Array http://docs.python.org/release/2.7.1/library/functions.html#bytearray

# do the appends need to include tags?

# support standards? for now, just version & segment?
# http://www.ccnx.org/releases/latest/doc/technical/NameConventions.html

# incorporate ccn_compare_names for canonical ordering?
#

from copy import copy
import time, struct, random

NAME_NORMAL = 0
NAME_ANY    = 1

class Name(object):
	def __init__(self, components=[], name_type=NAME_NORMAL):
		self.version = None      # need put/get handlers for attr
		self.segment = None
		self.type = name_type

		# pyccn
		self.ccn_data_dirty = True
		self.ccn_data = None  # backing charbuf

		if isinstance(components, self.__class__):
			self.components = copy(components.components)
			if not components.ccn_data_dirty:
				self.ccn_data = components.ccn_data
				self.ccn_data_dirty = False
		elif type(components) is str:
			self.setURI(components)
		else:
			self.components = copy(components)  # list of blobs

	def setURI(self, uri):
		ccn_data = _pyccn.name_from_uri(uri)
		self.components = _pyccn.name_comps_from_ccn(ccn_data)
		self.ccn_data = ccn_data
		self.ccn_data_dirty = False

	def appendKeyID(self, digest):
		component = b'\xc1.M.K\x00'
		component += digest
		self.components.append(component)
		self.ccn_data_dirty = True

	def appendVersion(self, version=None):
		if not version:
			inttime = int(time.time() * 4096 + 0.5)
			bintime = struct.pack("!Q", inttime)
			version = bintime.lstrip(b'\x00')
		component = b'\xfd' + version
		self.components.append(component)
		self.ccn_data_dirty = True

	def appendSegment(self, segment):
		component = b'\x00' + struct.pack('!Q', segment).lstrip(b'\x00')
		self.components.append(component)
		self.ccn_data_dirty = True

	def appendNonce(self):
		val = random.getrandbits(64)
		component = b'\xc1.N\x00' + struct.pack("@Q", val)
		self.components.append(component)
		self.ccn_data_dirty = True

	def appendNumeric(self):   # tagged numerics p4 of code
		pass

	def __str__(self):
		global NAME_NORMAL, NAME_ANY

		if self.type == NAME_NORMAL:
			return _pyccn.name_to_uri(self.ccn_data)
		elif self.type == NAME_ANY:
			return "<any>"
		else:
			raise ValueError("Name is of wrong type %d" % self.type)

	def __len__(self):
		return len(self.components)

	def __iadd__(self, component):
		self.ccn_data_dirty = True
		self.components.append(component)
		return self

	def __concat__(self, c):
		self.components.append(c)
		self.ccn_data_dirty = True

	def __setattr__(self, name, value):
		if name == 'components' or name == 'version' or name == 'segment' or name == 'ccn_data':
			self.ccn_data_dirty=True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name == "ccn_data":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				self.ccn_data = _pyccn.name_comps_to_ccn(self.components)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

	def __getitem__(self, key):
		if type(key) is int:
			return self.components[key]
		elif type(key) is slice:
			return Name(self.components[key])
		else:
			raise ValueError("Unknown __getitem__ type: %s" % type(key))

	def __setitem__(self, key, value):
		self.components[key] = value

	def __delitem__(self, key):
		del self.components[key]

	def __len__(self):
		return len(self.components)

	def __lt__(self, other):
		return _pyccn.compare_names(self.ccn_data, other.ccn_data) < 0

	def __gt__(self, other):
		return _pyccn.compare_names(self.ccn_data, other.ccn_data) > 0

	def __eq__(self, other):
		return _pyccn.compare_names(self.ccn_data, other.ccn_data) == 0

	def __le__(self, other):
		return _pyccn.compare_names(self.ccn_data, other.ccn_data) <= 0

	def __ge__(self, other):
		return _pyccn.compare_names(self.ccn_data, other.ccn_data) >= 0

	def __ne__(self, other):
		return _pyccn.compare_names(self.ccn_data, other.ccn_data) != 0
