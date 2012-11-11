#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#             Jeff Burke <jburke@ucla.edu>
#

# Upcall Result
RESULT_ERR               = -1 # upcall detected an error
RESULT_OK                =  0 # normal upcall return
RESULT_REEXPRESS         =  1 # reexpress the same interest again
RESULT_INTEREST_CONSUMED =  2 # upcall claims to consume interest
RESULT_VERIFY            =  3 # force an unverified result to be verified
RESULT_FETCHKEY          =  4 # request fetching of an unfetched key

# Upcall kind
UPCALL_FINAL              = 0 # handler is about to be deregistered
UPCALL_INTEREST           = 1 # incoming interest
UPCALL_CONSUMED_INTEREST  = 2 # incoming interest, someone has answered
UPCALL_CONTENT            = 3 # incoming verified content
UPCALL_INTEREST_TIMED_OUT = 4 # interest timed out
UPCALL_CONTENT_UNVERIFIED = 5 # content that has not been verified
UPCALL_CONTENT_BAD        = 6 # verification failed

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

	#If you're getting strange errors in upcall()
	#check your code whether you're returning a value
	def upcall(self, kind, upcallInfo):
		global RESULT_OK

		print('upcall', self, kind, upcallInfo)
		return RESULT_OK

class UpcallInfo(object):
	def __init__(self):
		self.ccn = None  # CCN object (not used)
		self.Interest = None  # Interest object
		self.matchedComps = None  # int
		self.ContentObject = None  # Content object

	def __str__(self):
		ret = "ccn = %s" % self.ccn
		ret += "\nInterest = %s" % self.Interest
		ret += "\nmatchedComps = %s" % self.matchedComps
		ret += "\nContentObject: %s" % str(self.ContentObject)
		return ret
