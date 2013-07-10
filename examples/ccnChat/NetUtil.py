#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#

import time
import ndn

class FlowController(ndn.Closure):
	def __init__(self, prefix, handle):
		self.prefix = ndn.Name(prefix)
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
		if kind in [ndn.UPCALL_FINAL, ndn.UPCALL_CONSUMED_INTEREST]:
			return ndn.RESULT_OK

		if kind != ndn.UPCALL_INTEREST:
			print("Got weird upcall kind: %d" % kind)
			return ndn.RESULT_ERR

		f = lambda elem: self.dispatch(info.Interest, elem)

		new = []
		consumed = False
		for elem in self.content_objects:
			if consumed or f(elem):
				new.append(elem)
				continue
			consumed = True
		self.content_objects = new

		return ndn.RESULT_INTEREST_CONSUMED if consumed else ndn.RESULT_OK

class VersionedPull(ndn.Closure):
	def __init__(self, base_name, callback, handle=None, version=None, latest=True):
		handle = handle or ndn.Face()

		# some constants
		self.version_marker = '\xfd'
		self.first_version_marker = self.version_marker
		self.last_version_marker = '\xfe\x00\x00\x00\x00\x00\x00'

		self.base_name = ndn.Name(base_name)
		self.callback = callback
		self.handle = handle
		self.latest_version = version or self.first_version_marker
		self.start_with_latest = latest

	def build_interest(self, latest):
		if self.start_with_latest:
			latest=True
			self.start_with_latest = False

		excl = ndn.ExclusionFilter()
		excl.add_any()
		excl.add_name(ndn.Name([self.latest_version]))
		# expected result should be between those two names
		excl.add_name(ndn.Name([self.last_version_marker]))
		excl.add_any()

		interest = ndn.Interest(name=self.base_name, exclude=excl, \
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
		if kind == ndn.UPCALL_FINAL:
			return ndn.RESULT_OK

		# update version
		if kind in [ndn.UPCALL_CONTENT, ndn.UPCALL_CONTENT_UNVERIFIED]:
			base_len = len(self.base_name)
			self.latest_version = info.ContentObject.name[base_len]

		self.callback(kind, info)

		return ndn.RESULT_OK

if __name__ == '__main__':
	from ndn import _ndn, Key, ContentObject

	def publish(name, content):
		key = ndn.Face.getDefaultKey()
		keylocator = ndn.KeyLocator(key)

		# Name
		co_name = ndn.Name(name).appendSegment(0)

		# SignedInfo
		si = ndn.SignedInfo()
		si.type = ndn.CONTENT_DATA
		si.finalBlockID = ndn.Name.num2seg(0)
		si.publisherPublicKeyDigest = key.publicKeyID
		si.keyLocator = keylocator

		# ContentObject
		co = ndn.ContentObject()
		co.content = content
		co.name = co_name
		co.signedInfo = si

		co.sign(key)
		return co

	def callback(kind, info):
		print(info.ContentObject.content)

	fc = FlowController("/test", ndn.Face())
	fc.put(publish('/test/1', 'one'))
	fc.put(publish('/test/2', 'two'))
	fc.put(publish('/test/3', 'three'))
	vp = VersionedPull("/chat", callback)
	el = ndn.EventLoop(fc.handle, vp.handle)

	while True:
		vp.requestNext()
		el.run_once()
		time.sleep(1)
