from pyccn import Interest, Name, Key, CCN, _pyccn
import datetime

h = CCN.CCN()
k = h.getDefaultKey()
del h

i = Interest.Interest()
i.name = Name.Name('/hello/world')
i.minSuffixComponents = 2
i.maxSuffixComponents = 4
i.publisherPublicKeyDigest = k.publicKeyID
i.exclude = None
i.childSelector = 1
i.answerOriginKind = 4
i.scope = 1
i.interestLifetime = 30.0
i.nonce = 'abababa'

print(i)
print(i.ccn_data)

i2 = _pyccn._pyccn_Interest_from_ccn(i.ccn_data)
print(i2)
