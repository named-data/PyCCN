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

#Upcall Result
UPCALL_RESULT_ERR               = -1 # upcall detected an error
UPCALL_RESULT_OK                =  0 # normal upcall return
UPCALL_RESULT_REEXPRESS         =  1 # reexpress the same interest again
UPCALL_RESULT_INTEREST_CONSUMED =  2 # upcall claims to consume interest
UPCALL_RESULT_VERIFY            =  3 # force an unverified result to be verified

#Upcall kind
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
		global UPCALL_RESULT_OK

		# override to be call
		print('upcall', self, kind, upcallInfo)
		return UPCALL_RESULT_OK

class UpcallInfo(object):
	def __init__(self):
		self.ccn = None  # CCN object
		self.Interest = None  # Interest object
		self.matchedComps = None  # int
		self.ContentObject = None  # Content object
		self.ccn_data = None #CCN representation

	def __str__(self):
		ret = "ccn = %s" % self.ccn
		ret += "\nInterest = %s" % self.Interest
		ret += "\nmatchedComps = %s" % self.matchedComps
		ret += "\nContentObject: %s" % str(self.ContentObject)
		return ret
