import sys
import pyccn

class ccnput(pyccn.Closure):
	def __init__(self, name, content):
		self.handle = pyccn.CCN()
		self.name = pyccn.Name(name)
		self.content = self.prepareContent(content, self.handle.getDefaultKey())

	# this is so we don't have to do signing each time someone requests data
	# if we will be serving content multiple times
	def prepareContent(self, content, key):
		# create a new data packet
		co = pyccn.ContentObject()

		# since they want us to use versions and segments append those to our name
		co.name = self.name.appendVersion().appendSegment(0)

		# place the content
		co.content = content

		si = co.signedInfo

		# key used to sign data (required by ccnx)
		si.publisherPublicKeyDigest = key.publicKeyID

		# how to obtain the key (required by ccn); here we attach the
		# key to the data (not too secure), we could also provide name
		# of the key under which it is stored in DER format
		si.keyLocator = pyccn.KeyLocator(key)

		# data type (not needed, since DATA is the default)
		si.type = pyccn.CONTENT_DATA

		# number of the last segment (0 - i.e. this is the only
		# segment)
		si.finalBlockID = pyccn.Name.num2seg(0)

		# signing the packet
		co.sign(key)

		return co

	# Called when we receive interest
	# once data is sent signal ccn_run() to exit
	def upcall(self, kind, info):
		if kind != pyccn.UPCALL_INTEREST:
			return pyccn.RESULT_OK

		self.handle.put(self.content) # send the prepared data
		self.handle.setRunTimeout(0) # finish run() by changing its timeout to 0

		return pyccn.RESULT_INTEREST_CONSUMED

	def start(self):
		# register our name, so upcall is called when interest arrives
		self.handle.setInterestFilter(self.name, self)

		print "listening ..."

		# enter ccn loop (upcalls won't be called without it, get
		# doesn't require it as well)
		# -1 means wait forever
		self.handle.run(-1)

def usage():
	print("Usage: %s <uri>" % sys.argv[0])
	print("Reads data from stdin and sends it")
	sys.exit(1)

if __name__ == '__main__':
	if len(sys.argv) != 2:
		usage()
	if sys.stdin.isatty():
		usage()

	name = sys.argv[1]
	content = sys.stdin.read()

	put = ccnput(name, content)
	put.start()

