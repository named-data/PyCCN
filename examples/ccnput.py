import sys
from pyccn import CCN, Name, Interest, ContentObject, Key, Closure

class ccnput(Closure.Closure):
	def __init__(self, name, content):
		self.handle = CCN.CCN()
		self.name = Name.Name(name)
		self.content = self.prepareContent(content, self.handle.getDefaultKey())

	# this is so we don't have to do signing each time someone requests data
	# if we will be serving content multiple times
	def prepareContent(self, content, key):
		co = ContentObject.ContentObject()

		# since they want us to use versions and segments append those to our name
		co.name = Name.Name(self.name) # making copy, so any changes to co.name won't change self.name
		co.name.appendVersion() # timestamp which is our version
		co.name += b'\x00' # first segment

		co.content = content

		si = co.signedInfo
		si.publisherPublicKeyDigest = key.publicKeyID
		si.type = ContentObject.CONTENT_DATA
		si.finalBlockID = b'\x00' # no more segments available
		si.keyLocator = Key.KeyLocator(key)

		co.sign(key)
		return co

	# Called when we receive interest
	# once data is sent signal ccn_run() to exit
	def upcall(self, kind, info):
		if kind != Closure.UPCALL_INTEREST:
			return Closure.RESULT_OK

		self.handle.put(self.content) # send the prepared data
		self.handle.setRunTimeout(0) # finish run()

		return Closure.RESULT_INTEREST_CONSUMED

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
