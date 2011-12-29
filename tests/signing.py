import pyccn

k = pyccn.CCN.getDefaultKey()

co = pyccn.ContentObject()
try:
	co.sign(k)
except AttributeError:
	pass
else:
	raise AssertionError("this should fail!")

co.name = pyccn.Name("/foo/foo")
co.signedInfo = pyccn.SignedInfo()
co.signedInfo.publisherPublicKeyDigest = k.publicKeyID
co.signedInfo.type = pyccn.CONTENT_DATA
co.signedInfo.freshness = -1
co.content = "hello!"
co.sign(k)

