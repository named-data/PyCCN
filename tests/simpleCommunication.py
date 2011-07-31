from pyccn import CCN, Name, Interest, ContentObject, Key
from threading import Timer

k = Key.Key()
k.generateRSA(1024)

kl = Key.KeyLocator()
kl.key = k

n = Name.Name()
n.setURI("/foo/foo")

co = ContentObject.ContentObject()
co.name = n
co.content = "Frou"

si = ContentObject.SignedInfo()
si.publisherPublicKeyDigest = k.publicKeyID
si.type = 0x0C04C0
si.freshnessSeconds = -1

co.signedInfo = si
co.sign(k)

c = CCN.CCN()

print c.put(co)

#def push_data(co):
#	c.put(co)
#push_data(co)

#t = Timer(1.0, push_data, co)

#i = Interest.Interest()

#co2 = c.get(n, i, 5000)
#t.start()
#print co2






#k = Key.Key()
#k.generateRSA(1024)

#kl = Key.KeyLocator()
#kl.key = k

#n = Name.Name(["Foo", "Foo"])

#co = ContentObject.ContentObject()
#co.name = n
#co.content = "Frou"

#si = ContentObject.SignedInfo()
#si.publisherPublicKeyDigest = k.publicKeyID
#si.type = 0x0C04C0
#si.freshnessSeconds = -1

#co.signedInfo = si
#co.sign(k)

#def push_data(co):
#	c.put(co)
#push_data(co)

#t = Timer(1.0, push_data, co)

#i = Interest.Interest()

#co2 = c.get(n, i, 5000)
#t.start()
#print co2
