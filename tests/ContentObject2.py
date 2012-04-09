import pyccn
import pyccn._pyccn as _pyccn

k = pyccn.CCN.getDefaultKey()

kl = pyccn.KeyLocator(k)

i = pyccn.Interest()
i.name = pyccn.Name('/chat')
i.minSuffixComponents = 3
i.maxSuffixComponents = 3
i.childSelector = 1

co = pyccn.ContentObject()
co.name = pyccn.Name('/chat/%FD%04%E6%93.%18K/%00')
co.content = "number 0"
co.signedInfo.publisherPublicKeyDigest = k.publicKeyID
co.signedInfo.finalBlockID = b'\x00'
co.sign(k)

print(str(co))

co2 = _pyccn.ContentObject_obj_from_ccn(co.ccn_data)
print(str(co2))

print(str(i))

print(co.matchesInterest(i))
