# Front ccn_parsed_interest.
# Sort of.

#
#    //  IMPORTANT:  Exclusion component list must be sorted following "Canonical CCNx ordering"
#    //              http://www.ccnx.org/releases/latest/doc/technical/CanonicalOrder.html
#    //              in which shortest components go first.
#

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
		self.ccn_data_dirty = False
		self.ccn_data = None  # backing charbuf
		self.ccn_data_parsed = None  # backing parsed interest

# Bloom filters will be deprecated, so we do not support them.
class ExclusionFilter(object):
	def __init__(self):
		self.data = None        # shoudl this be a list?
		# pyccn
		self.ccn_data_dirty = False
		self.ccn_data = None  # backing charbuf

	def __get_ccn(self):
		pass

