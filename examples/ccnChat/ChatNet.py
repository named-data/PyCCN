from pyccn import CCN, Name, Interest, Key, ContentObject, Closure
import logging
import sys, threading, getpass, time

logging.basicConfig(filename='chat.log', level=logging.DEBUG)
log = logging.getLogger("ChatNet")

# This is so we can convert from utf-8 to unicode in a compatible way
if sys.version >= '3':
	unicode = str

class ChatNet(object):
	def __init__(self, prefix, callback):
		self.last_text = None
		self.callback = callback
		self.friendly_names = {}

		self.interest_tmpl = Interest.Interest(maxSuffixComponents=3, \
			minSuffixComponents=3, childSelector=1, answerOriginKind=0)

		self.handle = CCN.CCN()
		self.chat_uri = Name.Name(prefix)
		self.members_uri = Name.Name(prefix)
		self.members_uri += "members"

		self.default_key = self.handle.getDefaultKey()
		digest = self.default_key.publicKeyID
		#TODO: digests should be bytes not bytearrays
		if type(digest) is bytearray:
			log.warning("XXX: Converting digest from bytearray to bytes!")
			digest = bytes(digest)
		self.friendly_names[digest] = getpass.getuser()

	def pullData(self):
		co = self.handle.get(self.chat_uri, self.interest_tmpl)
		if not co:
			return False

		text = unicode(co.content, "utf-8", "replace")
		if text == self.last_text:
			return False

		digest = co.signedInfo.publisherPublicKeyDigest

		#TODO: digests should be bytes not bytearrays
		if type(digest) is bytearray:
			log.warning("XXX: Converting digest from bytearray to bytes!")
			digest = bytes(digest)

		nick = self.get_friendly_name(digest)

		self.callback(nick, text)
		self.last_text = text

	def get_friendly_name(self, digest):
		if digest in self.friendly_names:
			return self.friendly_names.get(digest)

		n = Name.Name(self.members_uri)
		n.appendKeyID(digest)
		co = self.handle.get(n, self.interest_tmpl)
		if not co:
			return "~unknown~"

		nick = unicode(co.content, "utf-8", "replace")
		self.friendly_names[digest] = nick

		return nick

class ChatServer(Closure.Closure):
	def __init__(self, namespace):
		self.user = getpass.getuser()

		self.handle = CCN.CCN()

		#XXX: temporary, until we allow fetching key from key storage
		self.key = self.handle.getDefaultKey()
		self.keylocator = Key.KeyLocator()
		self.keylocator.key = self.key

		self.prefix = Name.Name(namespace)
		self.members_uri = Name.Name(namespace)
		self.members_uri += "members"

		self.message = None
		self.member_message = None

	def listen(self):
		#listen to requests in namespace
		self.handle.setInterestFilter(self.prefix, self)
		self.handle.run(-1)

	def publish(self, name, content):
		# Name
		co_name = Name.Name(name)
		co_name.appendVersion()
		co_name += b'\x00'

		# SignedInfo
		si = ContentObject.SignedInfo()
		si.type = ContentObject.ContentType.CCN_CONTENT_DATA
		si.finalBlockID = b'\x00'
		si.publisherPublicKeyDigest = self.key.publicKeyID
		si.keyLocator = self.keylocator

		# ContentObject
		co = ContentObject.ContentObject()
		co.content = content
		co.name = co_name
		co.signedInfo = si

		co.sign(self.key)
		return co

	def publish_handle(self, interest):
		if not self.member_message:
			self.member_message = self.publish(interest.name, self.user)
		return self.handle.put(self.member_message)

	def send_message(self, message):
		name = Name.Name(self.prefix)
		co = self.publish(name, message)
		self.message = co
		self.handle.put(co) #this is using a bug in ccnx

	def upcall(self, kind, upcallInfo):
		interest = upcallInfo.Interest
		name = interest.name

		log.debug("Got request for: " + str(name.components))

		if self.message and interest.matches_name(self.prefix):
			log.debug("Publishing content")
			self.handle.put(self.message)
			return True

		if interest.matches_name(self.members_uri):
			log.debug("Publishing member's name")
			self.publish_handle(interest)
			return True

		log.error("Got unknown request: " + str(name.components))

		return False
