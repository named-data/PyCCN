#
# This example was written for older version of PyCCN and it is currently broken
#

from pyccn.Repository import RepoUpload
from pyccn import CCN, ContentObject, Name, Key
import struct

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
