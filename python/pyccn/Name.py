#
# Copyright (c) 2011, Regents of the University of California
# All rights reserved.
# Written by: Derek Kulinski <takeda@takeda.tk>
#             Jeff Burke <jburke@ucla.edu>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the Regents of the University of California nor
#       the names of its contributors may be used to endorse or promote
#       products derived from this software without specific prior written
#       permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL REGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
			ret += self.separator
			if type(c) is str:
				ret += c
			elif type(c) is bytearray or type(c) is bytes:
				ret += c.decode()
			else:
				ret += str(c)

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
