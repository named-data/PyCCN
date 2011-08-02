from pyccn import ContentObject, Key, CCN, Name

c = CCN.CCN()
k = c.getDefaultKey()

co = ContentObject.ContentObject()
try:
	co.sign(k)
except AttributeError:
	pass
else:
	raise AssertionError("this should fail!")

co.name = Name.Name("/foo/foo")
co.signedInfo = ContentObject.SignedInfo()
co.signedInfo.publisherPublicKeyDigest = k.publicKeyID
co.signedInfo.type = ContentObject.ContentType.CCN_CONTENT_DATA
co.signedInfo.freshness = -1
co.content = "hello!"
co.sign(k)
