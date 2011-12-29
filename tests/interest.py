from pyccn import Interest, Name, Key, CCN, _pyccn
import datetime

k = CCN.getDefaultKey()

i = Interest()
i.name = Name('/hello/world')
i.minSuffixComponents = 2
i.maxSuffixComponents = 4
i.publisherPublicKeyDigest = k.publicKeyID
i.exclude = None
i.childSelector = 1
i.answerOriginKind = 4
i.scope = 2
i.interestLifetime = 30.0
i.nonce = b'abababa'

print(i)
print(i.ccn_data)

i2 = _pyccn.Interest_obj_from_ccn(i.ccn_data)
print(i2)

assert(i.name == i2.name)
assert(i.minSuffixComponents == i2.minSuffixComponents)
assert(i.maxSuffixComponents == i2.maxSuffixComponents)
assert(i.publisherPublicKeyDigest == i2.publisherPublicKeyDigest)
assert(i.exclude == i2.exclude)
assert(i.childSelector == i2.childSelector)
assert(i.scope == i2.scope)
assert(i.interestLifetime == i2.interestLifetime)
assert(i.nonce == i2.nonce)
