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

# Front ccn_parsed_ContentObject.
# Sort of.
from . import _pyccn

from base64 import b64encode, b64decode
from binascii import a2b_hex

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
		self.ccn_data_dirty = True
		self.ccn_data = None  # backing charbuf
		self.ccn_data_parsed = None  # PCO
		self.ccn_data_components = None  # PCO

	# this is the finalization step
	# must pass a key here, there is no "default key" because
	# a CCN handle is not required to create the content object
	# thus there is no access to the ccn library keystore.
	#
	def sign(self, key):
		self.ccn_data = _pyccn._pyccn_ContentObject_to_ccn(self,
			self.name.ccn_data, self.content, self.signedInfo.ccn_data, key)
		self.ccn_data_dirty = False

	def digest(self):
		return _pyccn.digest_contentobject(self.ccn_data, self.ccn_data_parsed)

	def verify(self):
		# ccn_verify_content
		pass

	def matchesInterest(self, interest):
		return _pyccn.content_matches_interest(self.ccn_data, interest.ccn_data, \
			self.ccn_data_parsed, interest.ccn_data_parsed)

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
				print("Call sign() to finalize before accessing ccn_data for a ContentObject")
		return object.__getattribute__(self, name)

	# Where do we support versioning and segmentation?

	def __str__(self):
		ret = "Name: %s" % self.name
		ret += "\nContent: %s" % self.content.decode("utf-8", errors='replace')
		ret += "\nDigestAlg: %s" % self.digestAlgorithm
		ret += "\nSignedInfo: %s" % self.signedInfo
		return ret

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
				self.ccn_data = _pyccn._pyccn_SignedInfo_to_ccn(self.publisherPublicKeyDigest, self.type, key_locator=key_locator)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

	def __get_ccn(self):
		pass
		# Call ccn_signed_info_create

	def __str__(self):
		pubkeydigest = "<PublisherPublicKeyDigest>%s</PublisherPublicKeyDigest>" \
			% b64encode(self.publisherPublicKeyDigest)
		timestamp = "<Timestamp>%s</Timestamp>" % b64encode(self.timeStamp)
		type = "<Type>%s</Type>" % ("None" if self.type == None else "0x%0.6X" % self.type)
		freshness = "<FreshnessSeconds>%s<FreshnessSeconds>" % self.freshnessSeconds
		finalBlockID = "<FinalBlockID>%s</FinalBlockID>" % self.finalBlockID
		res = "<SignedInfo>%s%s%s%s%s%s</SignedInfo>" % (pubkeydigest, timestamp, type, freshness, finalBlockID, self.keyLocator)
		return res

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
