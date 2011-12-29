#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#             Jeff Burke <jburke@ucla.edu>
#

# Front ccn_parsed_ContentObject.
# Sort of.
from . import _pyccn

from base64 import b64encode, b64decode
from binascii import a2b_hex

CONTENT_DATA = 0x0C04C0
CONTENT_ENCR = 0x10D091
CONTENT_GONE = 0x18E344
CONTENT_KEY  = 0x28463F
CONTENT_LINK = 0x2C834A
CONTENT_NACK = 0x34008A

class ContentObject(object):
	def __init__(self, name=None, content=None, signed_info=None):
		self.name = name
		self.content = content

		self.signedInfo = signed_info if signed_info else SignedInfo()
		self.digestAlgorithm = None # Default

		# generated
		self.signature = None
		self.verified = False

		# pyccn
		self.ccn = None # Reference to CCN object
		self.ccn_data_dirty = True
		self.ccn_data = None  # backing charbuf

	# this is the finalization step
	# must pass a key here, there is no "default key" because
	# a CCN handle is not required to create the content object
	# thus there is no access to the ccn library keystore.
	#
	def sign(self, key):
		self.ccn_data = _pyccn.encode_ContentObject(self, self.name.ccn_data, \
			self.content, self.signedInfo.ccn_data, key)
		self.ccn_data_dirty = False

	def digest(self):
		return _pyccn.digest_contentobject(self.ccn_data)

	def verify_content(self, handle):
		return _pyccn.verify_content(handle.ccn_data, self.ccn_data)

	def verify_signature(self, key):
		return _pyccn.verify_signature(self.ccn_data, key.ccn_data_public)

	def matchesInterest(self, interest):
		return _pyccn.content_matches_interest(self.ccn_data, interest.ccn_data)

	def __setattr__(self, name, value):
		if name == 'name' or name == 'content' or name == 'signedInfo' or name == 'digestAlgorithm':
			self.ccn_data_dirty=True

		if name == 'content':
			object.__setattr__(self, name, _pyccn.content_to_bytes(value))
		else:
			object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name == "ccn_data":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				raise _pyccn.CCNContentObjectError("Call sign() to finalize \
					before accessing ccn_data for a ContentObject")
		return object.__getattribute__(self, name)

	# Where do we support versioning and segmentation?

	def __str__(self):
		ret = []
		ret.append("Name: %s" % self.name)
		ret.append("Content: %r" % self.content)
		ret.append("DigestAlg: %r" % self.digestAlgorithm)
		ret.append("SignedInfo: %s" % self.signedInfo)
		ret.append("Signature: %s" % self.signature)
		return "\n".join(ret)

class Signature(object):
	def __init__(self):
		self.digestAlgorithm = None
		self.witness = None
		self.signatureBits = None
		# pyccn
		self.ccn_data_dirty = False
		self.ccn_data = None  # backing charbuf

	def __setattr__(self, name, value):
		if name=='witness' or name=='signatureBits' or name=='digestAlgorithm':
			self.ccn_data_dirty=True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name=="ccn_data":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				self.ccn_data = _pyccn.Signature_obj_to_ccn(self)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

	def __str__(self):
		res = []
		res.append("digestAlgorithm = %s" % self.digestAlgorithm)
		res.append("witness = %s" % self.witness)
		res.append("signatureBits = %r" % self.signatureBits)
		return "\n".join(res)

class SignedInfo(object):
	def __init__(self, key_digest = None, key_locator = None, type = CONTENT_DATA,
			freshness = None, final_block = None, timestamp = None):

		self.publisherPublicKeyDigest = key_digest # SHA256 hash
		self.timeStamp = timestamp   # CCNx timestamp
		self.type = type
		self.freshnessSeconds = freshness
		self.finalBlockID = final_block
		self.keyLocator = key_locator

		# pyccn
		self.ccn_data_dirty = True
		self.ccn_data = None  # backing charbuf

	def __setattr__(self, name, value):
		if name != "ccn_data" and name != "ccn_data_dirty":
			self.ccn_data_dirty = True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name == "ccn_data":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				key_locator = self.keyLocator.ccn_data if self.keyLocator else None
				self.ccn_data = _pyccn.SignedInfo_to_ccn( \
					self.publisherPublicKeyDigest, self.type, self.timeStamp, \
					self.freshnessSeconds if self.freshnessSeconds else -1, \
					self.finalBlockID, key_locator)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

	def __get_ccn(self):
		pass
		# Call ccn_signed_info_create

	def __str__(self):
		pubkeydigest = "<PublisherPublicKeyDigest>%s</PublisherPublicKeyDigest>" \
			% b64encode(self.publisherPublicKeyDigest)
		timestamp = "<Timestamp>%s</Timestamp>" % (b64encode(self.timeStamp) if self.timeStamp else None)
		type = "<Type>%s</Type>" % ("None" if self.type == None else "0x%0.6X" % self.type)
		freshness = "<FreshnessSeconds>%s</FreshnessSeconds>" % self.freshnessSeconds
		finalBlockID = "<FinalBlockID>%r</FinalBlockID>" % self.finalBlockID
		res = "<SignedInfo>%s%s%s%s%s%s</SignedInfo>" % (pubkeydigest, timestamp, type, freshness, finalBlockID, self.keyLocator)
		return res

#Don't use this class, it is deprecated
class ContentType(object):
	CCN_CONTENT_DATA = 0x0C04C0
	CCN_CONTENT_ENCR = 0x10D091
	CCN_CONTENT_GONE = 0x18E344
	CCN_CONTENT_KEY  = 0x28463F
	CCN_CONTENT_LINK = 0x2C834A
	CCN_CONTENT_NACK = 0x34008A
#	CCN_CONTENT_DATA = b64decode("DATA")
#	CCN_CONTENT_ENCR = b64decode("ENCR")
#	CCN_CONTENT_GONE = b64decode("GONE")
#	CCN_CONTENT_KEY  = b64decode("KEY/")
#	CCN_CONTENT_LINK = b64decode("LINK")
#	CCN_CONTENT_NACK = b64decode("NACK")

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
