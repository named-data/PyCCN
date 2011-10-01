from pyccn import CCN, Closure, ContentObject, Interest, Key, Name
import struct

class RepoUpload(Closure.Closure):
	def __init__(self, handle, name, content):
		self.handle = handle
		self.name = Name.Name(name)
		self.content_objects = content

	def start(self):
		self.handle.setInterestFilter(self.name, self)

		interest = Interest.Interest(
			name = Name.Name(self.name))
		interest.name += '\xC1.R.sw'
		interest.name.appendNonce()

		print("Expressing interest: ccnx:%s" % interest.name)

		self.handle.expressInterest(interest.name, self, interest)
		self.handle.run(-1)

	def dispatch_content(self, interest, elem):
		if elem.matchesInterest(interest):
			print("serving: %s" % elem.name)
			self.handle.put(elem)
			return True
		return False

	def handle_interest(self, matched_comps, interest):
		f = lambda elem: self.dispatch_content(interest, elem)

		print("Received interest for: %s" % interest.name)

		consumed = False
		for i, elem in enumerate(self.content_objects):
			if f(elem):
				self.content_objects.pop(i)
				consumed = True
				break

		if len(self.content_objects) == 0:
			self.handle.setRunTimeout(0)

		return consumed

	def upcall(self, kind, info):
		if kind == Closure.UPCALL_FINAL:
			return Closure.RESULT_OK

		if kind == Closure.UPCALL_INTEREST:
			if self.handle_interest(info.matchedComps, info.Interest):
				return Closure.RESULT_INTEREST_CONSUMED
			else:
				return Closure.RESULT_OK

		print("- - - - -")
		print("kind: %d" % kind)
		print("name: %s" % info.Interest.name)
		return Closure.RESULT_OK

if __name__ == '__main__':
	def segment(segment):
		return b'\x00' + struct.pack('!Q', segment).lstrip('\x00')

	def publish(key, name, last_segment, content):
		print("Generating: %s" % name)

		# Name
		co_name = Name.Name(name)

		# SignedInfo
		si = ContentObject.SignedInfo()
		si.type = ContentObject.ContentType.CCN_CONTENT_DATA
		si.finalBlockID = last_segment
		si.publisherPublicKeyDigest = key.publicKeyID
		si.keyLocator = Key.KeyLocator(key)

		# ContentObject
		co = ContentObject.ContentObject()
		co.content = content
		co.name = co_name
		co.signedInfo = si

		co.sign(key)
		return co

	name = Name.Name('/repo/upload/test')
	name_v = Name.Name(name)
	name_v.appendVersion()

	handle = CCN.CCN()
	key = handle.getDefaultKey()
	last_seg = segment(9)

	content = []
	for i in range(10):
		name_s = Name.Name(name_v)
		name_s += segment(i)
		co = publish(key, name_s, last_seg, "Segment: %d\n" % i)
		content.append(co)

	upload = RepoUpload(handle, name_v, content)
	upload.start()
