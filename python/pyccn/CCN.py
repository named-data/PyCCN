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

# Fronts ccn

# ccn_handle is opaque to c struct

class CCN(object):
	def __init__(self):
		self.ccn_data = _pyccn._pyccn_ccn_create()   # CObject of ccn handle
		_pyccn._pyccn_ccn_connect(self.ccn_data)

	def run(self, timeoutms):
		_pyccn._pyccn_ccn_run(self.ccn_data, timeoutms)

	def setRunTimeout(self, timeoutms):
		_pyccn._pyccn_ccn_set_run_timeout(self.ccn_data, timeoutms)

	def __del__(self):
		del self.ccn_data

	# Application-focused methods
	#
	def expressInterest(self, name, closure, template=None):
		return _pyccn._pyccn_ccn_express_interest(self, name, closure, template)

	def setInterestFilter(self, name, closure, flags = None):
		if flags is None:
			return _pyccn._pyccn_ccn_set_interest_filter(self.ccn_data, name.ccn_data, closure)
		else:
			return _pyccn._pyccn_ccn_set_interest_filter(self.ccn_data, name.ccn_data, closure, flags)

	# Blocking!
	def get(self, name, template = None, timeoutms = 3000):
		return _pyccn._pyccn_ccn_get(self, name, template, timeoutms)

	def put(self, contentObject):
		return _pyccn._pyccn_ccn_put(self, contentObject)

	def getDefaultKey(self):
		return _pyccn._pyccn_ccn_get_default_key(self);

	# ?
	def loadDefaultKey(self):
		# we prefer explicit keys
		# ccn_load_default_key
		pass

	def loadPrivateKey(self, key):
		# A little different semantics?
		# ccn_load_private_key
		pass

	def getPublicKey(self):
		# ccn_get_public_key
		pass
