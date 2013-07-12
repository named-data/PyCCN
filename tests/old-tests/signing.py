import ndn

k = ndn.Face.getDefaultKey()

co = ndn.ContentObject()
try:
	co.sign(k)
except AttributeError:
	pass
else:
	raise AssertionError("this should fail!")

co.name = ndn.Name("/foo/foo")
co.signedInfo = ndn.SignedInfo()
co.signedInfo.publisherPublicKeyDigest = k.publicKeyID
co.signedInfo.type = ndn.CONTENT_DATA
co.signedInfo.freshness = -1
co.content = "hello!"
co.sign(k)

