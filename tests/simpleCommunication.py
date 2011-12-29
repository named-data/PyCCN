import pyccn
from pyccn import CCN, Name, Interest, ContentObject, SignedInfo, Key, KeyLocator, Closure
#from threading import Timer

k = CCN.getDefaultKey()
kl = KeyLocator(k)

n = Name("/forty/two")

class SenderClosure(Closure):
	def upcall(self, kind, upcallInfo):
		global sender_handle, n, k, kl

		print("Sender closure:")
		print(upcallInfo)

		co = ContentObject()
		co.name = Name(n)
		co.content = "Frou"

		si = SignedInfo()
		si.publisherPublicKeyDigest = k.publicKeyID
		si.type = pyccn.CONTENT_DATA
		si.freshnessSeconds = 5
		si.keyLocator = kl

		co.signedInfo = si

		co.sign(k)
		r = sender_handle.put(co)
		print("put(co) = ", r)
		#sender_handle.setRunTimeout(0)

		return pyccn.RESULT_INTEREST_CONSUMED

class ReceiverClosure(Closure):
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

		return pyccn.RESULT_OK

senderclosure = SenderClosure()
receiverclosure = ReceiverClosure()

sender_handle = CCN()
receiver_handle = CCN()

#Looks like the CCNx API doesn't deliver messages
#that we sent to ourselves, so we just push it
sender_handle.setInterestFilter(n, senderclosure)
#senderclosure.upcall(1, None)

i = Interest()
receiver_handle.expressInterest(n, receiverclosure, i)

upcall_called = False

print("Running loops")

#So sender closure is called
#sender_handle.run(500)

#So receiver closure is called
#receiver_handle.run(500)

# New way of doing this
event_loop = pyccn.EventLoop(sender_handle, receiver_handle)
event_loop.run()

assert upcall_called
