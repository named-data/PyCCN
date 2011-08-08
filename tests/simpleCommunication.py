from pyccn import CCN, Name, Interest, ContentObject, Key, Closure
#from threading import Timer

k = Key.Key()
k.generateRSA(1024)

kl = Key.KeyLocator()
#kl.keyName = Name.Name("/this/is/key")
kl.key = k

n = Name.Name()
n.setURI("/forty/two")

class SenderClosure(Closure.Closure):
	def upcall(self, kind, upcallInfo):
		global c, n, k, kl

		co = ContentObject.ContentObject()
		co.name = n
		co.content = "Frou"

		si = ContentObject.SignedInfo()
		si.publisherPublicKeyDigest = k.publicKeyID
		si.type = 0x0C04C0
		si.freshnessSeconds = -1
		si.keyLocator = kl

		co.signedInfo = si

		co.sign(k)
		print c.put(co)

class ReceiverClosure(Closure.Closure):
	def upcall(self, kind, upcallInfo):
		global c

		print "#Receiver# Got response %d" % kind
		if (kind == 4):
			raise AssertionError("Got timeout")

		c.setRunTimeout(1)

senderclosure = SenderClosure()
receiverclosure = ReceiverClosure()

c = CCN.CCN()

#Looks like the CCNx API doesn't deliver messages
#that we sent to ourselves, so we just push it
#c.setInterestFilter(n, senderclosure)
senderclosure.upcall(1, None)

i = Interest.Interest()
c.expressInterest(n, receiverclosure, i)

#co2 = c.get(n, i, 5000)
#print co2

c.run(5000)

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
