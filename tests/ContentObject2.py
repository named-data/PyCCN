import ndn
import ndn._ndn as _ndn

k = ndn.Face.getDefaultKey()

kl = ndn.KeyLocator(k)

i = ndn.Interest()
i.name = ndn.Name('/chat')
i.minSuffixComponents = 3
i.maxSuffixComponents = 3
i.childSelector = 1

co = ndn.ContentObject()
co.name = ndn.Name('/chat/%FD%04%E6%93.%18K/%00')
co.content = "number 0"
co.signedInfo.publisherPublicKeyDigest = k.publicKeyID
co.signedInfo.finalBlockID = b'\x00'
co.sign(k)

print(str(co))

co2 = _ndn.ContentObject_obj_from_ccn(co.ccn_data)
print(str(co2))

print(str(i))

print(co.matchesInterest(i))
