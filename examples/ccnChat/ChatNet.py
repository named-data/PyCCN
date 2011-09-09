#
# Copyright (c) 2011, Regents of the University of California
# All rights reserved.
# Written by: Derek Kulinski <takeda@takeda.tk>
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

from pyccn import CCN, Name, Interest, Key, ContentObject, Closure
import logging
import sys, threading, getpass, time

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

		self.handle = CCN.CCN()
		self.chat_uri = Name.Name(prefix)
		self.members_uri = Name.Name(prefix)
		self.members_uri += "members"

		self.net_pull = VersionedPull(self.chat_uri, None, handle=self.handle)

		self.default_key = self.handle.getDefaultKey();
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

		n = Name.Name(self.members_uri)
		n.appendKeyID(digest)
		co = self.handle.get(n)
		if not co:
			return "~unknown~"

		nick = unicode(co.content, "utf-8", "replace")
		self.friendly_names[digest] = nick

		return nick

class ChatServer(Closure.Closure):
	def __init__(self, prefix, nick=getpass.getuser()):
		self.handle = CCN.CCN()
		self.flow = FlowController(prefix, self.handle)

		#XXX: temporary, until we allow fetching key from key storage
		self.key = self.handle.getDefaultKey()
		self.keylocator = Key.KeyLocator(self.key)

		self.prefix = Name.Name(prefix)
		self.members_uri = Name.Name(prefix)
		self.members_uri += "members"

		member_name = Name.Name(self.members_uri)
		member_name.appendKeyID(fix_digest(self.key.publicKeyID))
		self.member_message = self.publish(member_name, nick)
		self.flow.put(self.member_message)

	def listen(self):
		#listen to requests in namespace
		#self.handle.setInterestFilter(self.prefix, self)
		self.handle.run(-1)

	def publish(self, name, content):
		# Name
		co_name = Name.Name(name)
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

	def send_message(self, message):
		name = Name.Name(self.prefix)
		name.appendVersion()
		co = self.publish(name, message)
		#self.message = co
		#self.handle.put(co) #this is using a bug in ccnx
		self.flow.put(co)

	def upcall(self, kind, upcallInfo):
		interest = upcallInfo.Interest
		name = interest.name

		log.debug("Got request for: %s" % name)

		if self.message.matchesInterest(interest):
			log.debug("Publishing content")
			self.handle.put(self.message)
			return Closure.UPCALL_RESULT_INTEREST_CONSUMED

		if self.member_message.matchesInterest(interest):
			log.debug("Publishing member's name")
			self.handle.put(self.member_message)
			return Closure.UPCALL_RESULT_INTEREST_CONSUMED

		log.error("Got unknown request: %s" % name)

		return Closure.RESULT_OK
