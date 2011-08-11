# Fronts ccn_closure.

class Closure(object):
	def __init__(self):
		#I don't think storing CCN's closure is needed
		#and it creates a reference loop, as of now both
		#of those variables are never set -- Derek
		#
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
		self.ccn_data = None #CCN representation

	def __str__(self):
		print "ccn = %s" % self.ccn
		print "Interest = %s" % self.Interest
		print "matchedComps = %s" % self.matchedComps
		print "ContentObject: %s" % str(self.ContentObject)
