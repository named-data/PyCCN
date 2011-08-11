import _pyccn

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
class Name(object):
	def __init__(self, components=list()):
		self.version = None      # need put/get handlers for attr
		self.segment = None
		self.separator = "/"
		self.scheme = "ccnx:"

		# pyccn
		self.ccn_data_dirty = True
		self.ccn_data = None  # backing charbuf

		if type(components) is str:
			self.setURI(components)
		else:
			self.components = components  # list of blobs

	def setURI(self, uri):
		self.ccn_data_dirty = True

		if uri.startswith(self.scheme):
			uri = uri[len(self.scheme):]

		self.components = uri.strip(self.separator).split(self.separator)

	# can we do this in python
	def appendNonce(self):
		pass

	def appendNumeric(self):   # tagged numerics p4 of code
		pass

	def __str__(self):
		ret = ""
		for c in self.components:
			ret += self.separator + str(c)
		return ret

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
				self.ccn_data = _pyccn._pyccn_Name_to_ccn(self.components)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

	# Should be called if ccn_name is accessed and ccn_name_dirty is true
	def __get_ccn(self):
		# name_init()
		# and so on...
		pass
