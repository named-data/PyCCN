# Front ccn_parsed_interest.
# Sort of.

#
#    //  IMPORTANT:  Exclusion component list must be sorted following "Canonical CCNx ordering"
#    //              http://www.ccnx.org/releases/latest/doc/technical/CanonicalOrder.html
#    //              in which shortest components go first.
#

import _pyccn
import Name

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
