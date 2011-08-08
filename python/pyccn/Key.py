# Fronts ccn_pkey.
import _pyccn

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

	def toPEM(self, cobjkey):
		pass

	def fromDER(self, cobjkey):
		pass

	def fromPEM(self, cobjkey):
		pass

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
