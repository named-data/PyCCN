#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#

#from pyccn import CCN, Name, Interest, Key, ContentObject, Closure
import logging
import sys, threading, getpass, time
import pyccn

from NetUtil import VersionedPull, FlowController

logging.basicConfig(filename='chat.log', level=logging.DEBUG)
log = logging.getLogger("ChatNet")

# This is so we can convert from utf-8 to unicode in a compatible way
if sys.version >= '3':
	unicode = str

def fix_digest(digest):
	if type(digest) is bytearray:
		log.warning("XXX: Converting digest from bytearray to bytes!")
		digest = bytes(digest)
	return digest

class ChatNet(object):
	def __init__(self, prefix, callback):
		self.gui_callback = callback
		self.friendly_names = {}

		self.handle = pyccn.CCN()
		self.chat_uri = pyccn.Name(prefix)
		self.members_uri = self.chat_uri + "members"

		self.net_pull = VersionedPull(self.chat_uri, None, handle=self.handle)

		self.default_key = self.handle.getDefaultKey()
		digest = fix_digest(self.default_key.publicKeyID)
		self.friendly_names[digest] = getpass.getuser()

	def pullData(self):
		co = self.net_pull.fetchNext()
		if not co:
			return

		text = unicode(co.content, "utf-8", "replace")
		digest = fix_digest(co.signedInfo.publisherPublicKeyDigest)
		nick = self.get_friendly_name(digest)

		self.gui_callback(nick, text)

	def get_friendly_name(self, digest):
		if digest in self.friendly_names:
			return self.friendly_names.get(digest)

		n = self.members_uri.appendKeyID(digest)
		co = self.handle.get(n)
		if not co:
			return "~unknown~"

		nick = unicode(co.content, "utf-8", "replace")
		self.friendly_names[digest] = nick

		return nick

class ChatServer(pyccn.Closure):
	def __init__(self, prefix, nick=getpass.getuser()):
		self.handle = pyccn.CCN()
		self.flow = FlowController(prefix, self.handle)

		#XXX: temporary, until we allow fetching key from key storage
		self.key = self.handle.getDefaultKey()
		self.keylocator = pyccn.KeyLocator(self.key)

		self.prefix = pyccn.Name(prefix)
		self.members_uri = self.prefix + "members"

		member_name = self.members_uri.appendKeyID(fix_digest(self.key.publicKeyID))
		self.member_message = self.publish(member_name, nick)
		self.flow.put(self.member_message)

	def listen(self):
		#listen to requests in namespace
		#self.handle.setInterestFilter(self.prefix, self)
		self.handle.run(-1)

	def publish(self, name, content):
		# Name
		co_name = name.appendSegment(0)

		# SignedInfo
		si = pyccn.SignedInfo()
		si.type = pyccn.CONTENT_DATA
		si.finalBlockID = pyccn.Name.num2seg(0)
		si.publisherPublicKeyDigest = self.key.publicKeyID
		si.keyLocator = self.keylocator

		# ContentObject
		co = pyccn.ContentObject()
		co.content = content
		co.name = co_name
		co.signedInfo = si

		co.sign(self.key)
		return co

	def send_message(self, message):
		name = self.prefix.appendVersion()
		co = self.publish(name, message)
		self.flow.put(co)

	def upcall(self, kind, upcallInfo):
		interest = upcallInfo.Interest
		name = interest.name

		log.debug("Got request for: %s" % name)

		if self.message.matchesInterest(interest):
			log.debug("Publishing content")
			self.handle.put(self.message)
			return pyccn.RESULT_INTEREST_CONSUMED

		if self.member_message.matchesInterest(interest):
			log.debug("Publishing member's name")
			self.handle.put(self.member_message)
			return pyccn.RESULT_INTEREST_CONSUMED

		log.error("Got unknown request: %s" % name)

		return pyccn.RESULT_OK
