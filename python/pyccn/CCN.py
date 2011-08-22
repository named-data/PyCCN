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
