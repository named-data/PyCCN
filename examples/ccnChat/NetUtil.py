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

from pyccn import Interest, Name, CCN, Closure
import time

class FlowController(Closure.Closure):
	def __init__(self, prefix, handle):
		self.prefix = Name.Name(prefix)
		self.handle = handle
		self.content_objects = []

		self.cleanup_time = 15 * 60 # keep responses for 15 min
		handle.setInterestFilter(self.prefix, self)

	def put(self, co):
		self.content_objects.append((time.time(), co))

	def dispatch(self, interest, elem):
		if time.time() - elem[0] > self.cleanup_time:
			return False
		elif elem[1].matchesInterest(interest):
			self.handle.put(elem[1])
			return False
		return True

	def upcall(self, kind, info):
		if kind in [Closure.UPCALL_FINAL, Closure.UPCALL_CONSUMED_INTEREST]:
			return Closure.RESULT_OK

		if kind != Closure.UPCALL_INTEREST:
			print("Got weird upcall kind: %d" % kind)
			return Closure.RESULT_ERR

		f = lambda elem: self.dispatch(info.Interest, elem)

		new = []
		consumed = False
		for elem in self.content_objects:
			if consumed or f(elem):
				new.append(elem)
				continue
			consumed = True
		self.content_objects = new

		return Closure.RESULT_INTEREST_CONSUMED if consumed else Closure.RESULT_OK

class VersionedPull(Closure.Closure):
	def __init__(self, base_name, callback, handle=CCN.CCN(), version=None, latest=True):
		# some constants
		self.version_marker = '\xfd'
		self.first_version_marker = self.version_marker
		self.last_version_marker = '\xfe\x00\x00\x00\x00\x00\x00'

		self.base_name = Name.Name(base_name)
		self.callback = callback
		self.handle = handle
		self.latest_version = version if version else self.first_version_marker
		self.start_with_latest = latest

	def build_interest(self, latest):
		if self.start_with_latest:
			latest=True
			self.start_with_latest = False

		excl = Interest.ExclusionFilter()
		excl.add_any()
		excl.add_name(Name.Name([self.latest_version]))
		# expected result should be between those two names
		excl.add_name(Name.Name([self.last_version_marker]))
		excl.add_any()

		interest = Interest.Interest(name=self.base_name, exclude=excl, \
			minSuffixComponents=3, maxSuffixComponents=3)
		interest.childSelector = 1 if latest else 0
		return interest

	def fetchNext(self, latest=False):
		interest = self.build_interest(latest)
		co = self.handle.get(interest.name, interest)

		if co:
			base_len = len(self.base_name)
			self.latest_version = co.name[base_len]

		return co

	def requestNext(self, latest=False):
		interest = self.build_interest(latest)
		self.handle.expressInterest(interest.name, self, interest)

	def upcall(self, kind, info):
		if kind == Closure.UPCALL_FINAL:
			return Closure.RESULT_OK

		# update version
		if kind in [Closure.UPCALL_CONTENT, Closure.UPCALL_CONTENT_UNVERIFIED]:
			base_len = len(self.base_name)
			self.latest_version = info.ContentObject.name[base_len]

		self.callback(kind, info)

		return Closure.RESULT_OK

if __name__ == '__main__':
	from pyccn import _pyccn, Key, ContentObject

	def publish(name, content):
		key = _pyccn._pyccn_ccn_get_default_key()
		keylocator = Key.KeyLocator(key)

		# Name
		co_name = Name.Name(name)
		co_name += b'\x00'

		# SignedInfo
		si = ContentObject.SignedInfo()
		si.type = ContentObject.ContentType.CCN_CONTENT_DATA
		si.finalBlockID = b'\x00'
		si.publisherPublicKeyDigest = key.publicKeyID
		si.keyLocator = keylocator

		# ContentObject
		co = ContentObject.ContentObject()
		co.content = content
		co.name = co_name
		co.signedInfo = si

		co.sign(key)
		return co

	def callback(kind, info):
		print(info.ContentObject.content)

	fc = FlowController("/test", CCN.CCN())
	fc.put(publish('/test/1', 'one'))
	fc.put(publish('/test/2', 'two'))
	fc.put(publish('/test/3', 'three'))
	vp = VersionedPull("/chat", callback)
	el = CCN.EventLoop(fc.handle, vp.handle)

	while True:
		vp.requestNext()
		el.run_once()
		time.sleep(1)
