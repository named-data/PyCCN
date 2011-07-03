
# Front ccn_parsed_ContentObject.
# Sort of.
import _pyccn

class ContentObject(object):
	def __init__(self):
		self.name = None
		self.content = None
		self.signedInfo = None
		self.digestAlgorithm = None # Default

		# generated
		self.signature = None
		self.verified = False

		# pyccn
		self.ccn = None # Reference to CCN object
		self.ccn_data_dirty = False
		self.ccn_data = None  # backing charbuf
		self.ccn_data_parsed = None  # PCO
		self.ccn_data_components = None  # PCO

	# this is the finalization step
	# must pass a key here, there is no "default key" because
	# a CCN handle is not required to create the content object
	# thus there is no access to the ccn library keystore.
	#
	def sign(self, key):
		self.ccn_data = _pyccn._pyccn_ContentObject_to_ccn(self, key)
		self.ccn_data_dirty = False

	def verify(self):
		# ccn_verify_content
		pass

	def matchesInterest(self, interest):
		#ccn_content_matches_interest
		pass

	def __setattr__(self, name, value):
		if name=='name' or name=='content' or name=='signedInfo' or name=='digestAlgorithm':
			self.ccn_data_dirty=True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name=="ccn_data":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				print "Call sign() to finalize before accessing ccn_data for a ContentObject"
		return object.__getattribute__(self, name)

	# Where do we support versioning and segmentation?


class Signature(object):
	def __init__(self):
		self.digestAlgorithm = None
		self.witness = None
		self.signatureBits = None
		# pyccn
		self.ccn_data_dirty = False
		self.ccn_data = None  # backing charbuf

	def __get_ccn(self):
		pass

	def __setattr__(self, name, value):
		if name=='witness' or name=='signatureBits' or name=='digestAlgorithm':
			self.ccn_data_dirty=True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name=="ccn_data":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				self.ccn_data = _pyccn._pyccn_Signature_to_ccn(self)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

class SignedInfo(object):
	def __init__(self):
		self.publisherPublicKeyDigest = None     # SHA256 hash
		self.timeStamp = None   # CCNx timestamp
		self.type = None  # enum
		self.freshnessSeconds = None
		self.finalBlockID = None
		self.keyLocator = None
		# pyccn
		self.ccn_data_dirty = False
		self.ccn_data = None  # backing charbuf

	def __setattr__(self, name, value):
		if name != "ccn_data" and name != "ccn_data_dirty":
			self.ccn_data_dirty=True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name=="ccn_data":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				self.ccn_data = _pyccn._pyccn_SignedInfo_to_ccn(self)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

	def __get_ccn(self):
		pass
		# Call ccn_signed_info_create

class ContentType(object):
	CCN_CONTENT_DATA = 0x0C04C0
	CCN_CONTENT_ENCR = 0x10D091
	CCN_CONTENT_GONE = 0x18E344
	CCN_CONTENT_KEY  = 0x28463F
	CCN_CONTENT_LINK = 0x2C834A
	CCN_CONTENT_NACK = 0x34008A


#
#
# These are not used in signing in Python (all the info needed is in SignedInfo)
# But it is here in case the parsing of the c library version of signing params
# is needed.

class SigningParams(object):
	CCN_SP_TEMPL_TIMESTAMP      = 0x0001
	CCN_SP_TEMPL_FINAL_BLOCK_ID = 0x0002
	CCN_SP_TEMPL_FRESHNESS      = 0x0004
	CCN_SP_TEMPL_KEY_LOCATOR    = 0x0008
	CCN_SP_FINAL_BLOCK          = 0x0010
	CCN_SP_OMIT_KEY_LOCATOR     = 0x0020

	def __init__(self):
		self.flags;       # Use the CCN_SP flags above
		self.type;        # Content type, really should be somewhere else, it's not that related to signing
		self.freshness;

		# These three are only relevant, for now, if they are coming *from* a c object
		# otherwise, API version is filled in from CCN_SIGNING_PARAMS_INIT and
		# both template and key will come from the ContentObject's SignedInfo object
		self.apiVersion;
		self.template;    # SignedInfo referred to by this content object,
		self.key;         # Key to use - this should filled by a lookup against content object's signedinfo,

		# pyccn
		self.ccn_data_dirty = False
		self.ccn_data = None  # backing ccn_signing_params

	def __setattr__(self, name, value):
		if name != "ccn_data" and name != "ccn_data_dirty":
			self.ccn_data_dirty=True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name=="ccn_data":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				self.ccn_data = _pyccn._pyccn_SigningParams_to_ccn(self)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

	def __get_ccn(self):
		pass
		# Call ccn_signed_info_create

