from pyccn import CCN, Name, Interest, ContentObject, Key, Closure
#from threading import Timer

k = Key.Key()
k.generateRSA(1024)

kl = Key.KeyLocator(k)

n = Name.Name()
n.setURI("/forty/two")

class SenderClosure(Closure.Closure):
	def upcall(self, kind, upcallInfo):
		global sender_handle, n, k, kl

		print("Sender closure:")
		print(upcallInfo)

		co = ContentObject.ContentObject()
		co.name = Name.Name(n)
		co.content = "Frou"

		si = ContentObject.SignedInfo()
		si.publisherPublicKeyDigest = k.publicKeyID
		si.type = 0x0C04C0
		si.freshnessSeconds = 5
		si.keyLocator = kl

		co.signedInfo = si

		co.sign(k)
		r = sender_handle.put(co)
		print("put(co) = ", r)
		#sender_handle.setRunTimeout(0)

		return Closure.RESULT_INTEREST_CONSUMED

class ReceiverClosure(Closure.Closure):
	def upcall(self, kind, upcallInfo):
		global receiver_handle, upcall_called, event_loop

		print("Receiver closure:")

		print(upcallInfo)

		print("#Receiver# Got response %d" % kind)
		if (kind == 4):
			raise AssertionError("Got timeout")

		upcall_called = True
		#receiver_handle.setRunTimeout(0)
		event_loop.stop()

		return Closure.RESULT_OK

senderclosure = SenderClosure()
receiverclosure = ReceiverClosure()

sender_handle = CCN.CCN()
receiver_handle = CCN.CCN()

#Looks like the CCNx API doesn't deliver messages
#that we sent to ourselves, so we just push it
sender_handle.setInterestFilter(n, senderclosure)
#senderclosure.upcall(1, None)

i = Interest.Interest()
receiver_handle.expressInterest(n, receiverclosure, i)

upcall_called = False

print("Running loops")

#So sender closure is called
#sender_handle.run(500)

#So receiver closure is called
#receiver_handle.run(500)

# New way of doing this
event_loop = CCN.EventLoop(sender_handle, receiver_handle)
event_loop.run()

assert upcall_called
