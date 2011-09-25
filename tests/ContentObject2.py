from pyccn import CCN, ContentObject, Interest, Name, Key, _pyccn

h = CCN.CCN()
k = h.getDefaultKey()
del h

kl = Key.KeyLocator(k)

i = Interest.Interest()
i.name = Name.Name('/chat')
i.minSuffixComponents = 3
i.maxSuffixComponents = 3
i.childSelector = 1

co = ContentObject.ContentObject()
co.name = Name.Name('/chat/%FD%04%E6%93.%18K/%00')
co.content = "number 0"
co.signedInfo.publisherPublicKeyDigest = k.publicKeyID
co.signedInfo.finalBlockID = b'\x00'
co.sign(k)

print(str(co))

co2 = _pyccn.ContentObject_obj_from_ccn(co.ccn_data)
print(str(co2))

print(str(i))

print(co.matchesInterest(i))
