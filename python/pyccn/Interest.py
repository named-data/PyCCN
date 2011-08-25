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

# Front ccn_parsed_interest.
# Sort of.

#
#    //  IMPORTANT:  Exclusion component list must be sorted following "Canonical CCNx ordering"
#    //              http://www.ccnx.org/releases/latest/doc/technical/CanonicalOrder.html
#    //              in which shortest components go first.
#

from . import _pyccn
from . import Name

class Interest(object):
	def __init__(self):
		self.name = None  # Start from None to use for templates?
		self.minSuffixComponents = None  # default 0
		self.maxSuffixComponents = None  # default infinity
		self.publisherPublicKeyDigest = None   # SHA256 hash
		self.exclude = None
		self.childSelector = None
		self.answerOriginKind = None
		self.scope  = None
		self.interestLifetime = None
		self.nonce = None
		# pyccn
		self.ccn = None # Reference to CCN object
		self.ccn_data_dirty = True
		self.ccn_data = None  # backing charbuf
		self.ccn_data_parsed = None  # backing parsed interest

	def __setattr__(self, name, value):
		if name != "ccn_data_dirty":
			self.ccn_data_dirty = True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name == "ccn_data" or name == "ccn_data_parsed":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				self.ccn_data, self.ccn_data_parsed = _pyccn._pyccn_Interest_to_ccn(self)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

# Bloom filters will be deprecated, so we do not support them.
class ExclusionFilter(object):
	def __init__(self):
		self.data = None        # should this be a list?
		# pyccn
		self.ccn_data_dirty = False
		self.ccn_data = None  # backing charbuf

	def __get_ccn(self):
		pass
