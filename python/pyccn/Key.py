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

# Fronts ccn_pkey.
from . import _pyccn

class Key(object):
	def __init__(self):
		self.type = None
		self.publicKeyID = None # SHA256 hash
		self.publicKeyIDsize = 32
		self.pubid = None   # should load all keys into ccn's handle and hold their ID?
		# pyccn
		self.ccn_data_dirty = False
		self.ccn_data_public = None  # backing pkey
		self.ccn_data_private = None # backing pkey

	def __get_ccn(self):
		pass

	def generateRSA(self, numbits):
		_pyccn._pyccn_generate_RSA_key(self, numbits)

	def toDER(self, cobjkey):
		pass

	def privateToPEM(self, filename = None):
		if not self.ccn_data_private:
			raise _pyccn.CCNKeyError("Key is not private")

		if filename:
			f = open(filename, 'w')
			_pyccn.PEM_write_key(self.ccn_data_private, file=f)
			f.close()

	def publicToPEM(self, filename = None):
		if filename:
			f = open(filename, 'w')
			_pyccn.PEM_write_key(self.ccn_data_public, file=f)
			f.close()

	def fromDER(self, cobjkey):
		pass

	def fromPEM(self, filename = None):
		if filename:
			f = open(filename, 'r')
			(self.ccn_data_private, self.ccn_data_public, self.publicKeyID, \
				self.publicKeyIDsize) = _pyccn.PEM_read_key(f)
			f.close()

# plus library helper functions to generate and serialize keys?

class KeyLocator(object):
	def __init__(self):
		#whichever one is not none will be used
		#if multiple set, checking order is: keyName, key, certificate
		self.key = None
		self.certificate = None
		self.keyName = None
		# pyccn
		self.ccn_data_dirty = True
		self.ccn_data = None  # backing charbuf

	def __setattr__(self, name, value):
		if name != "ccn_data" and name != "ccn_data_dirty":
			self.ccn_data_dirty = True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name=="ccn_data":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				if object.__getattribute__(self, 'keyName'):
					self.ccn_data = _pyccn._pyccn_KeyLocator_to_ccn(
						name=self.keyName.ccn_data)
				elif object.__getattribute__(self, 'key'):
					self.ccn_data = _pyccn._pyccn_KeyLocator_to_ccn(
						key=self.key.ccn_data_public)
				elif object.__getattribute__(self, 'certificate'):
					#same but with cert= arg
					raise NotImplementedError("certificate support is not implemented")
				else:
					raise TypeError("No name, key nor certificate defined")

				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)
