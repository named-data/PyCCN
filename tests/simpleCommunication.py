from pyccn import CCN, Name, Interest, ContentObject, Key, Closure
#from threading import Timer

k = Key.Key()
k.generateRSA(1024)

kl = Key.KeyLocator()
kl.key = k

n = Name.Name()
n.setURI("/forty/two")

class MyClosure(Closure.Closure):
	def upcall(self, kind, upcallInfo):
		global c, n, k, kl

		print "O hai!"

		co = ContentObject.ContentObject()
		co.name = n
		co.content = "Frou"

		si = ContentObject.SignedInfo()
		si.publisherPublicKeyDigest = k.publicKeyID
		si.type = 0x0C04C0
		si.freshnessSeconds = -1
		si.keyLocator = kl

		co.signedInfo = si

		print "signing"
		co.sign(k)
		print "outputting"

		print c.put(co)

closure = MyClosure()
c = CCN.CCN()
c.setInterestFilter(n, closure)
c.run(10000)

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
