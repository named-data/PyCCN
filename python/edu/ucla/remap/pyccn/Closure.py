# Fronts ccn_closure.

class Closure(object):
	def __init__(self):
		# Use instance variables to return data to callback
		self.ccn_data = None  # this holds the ccn_closure
		self.ccn_data_dirty = False
		pass

	def upcall(self, kind, upcallInfo):
		# override to be call
		print 'upcall', self, kind, upcallInfo

class UpcallInfo(object):
	def __init__(self):
		self.ccn = None  # CCN object
		self.Interest = None  # Interest object
		self.matchedComps = None  # int
		self.ContentObject = None  # Content object

