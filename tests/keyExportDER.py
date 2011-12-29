import os, filecmp
from base64 import b64encode, b64decode
from pyccn import Key, _pyccn, CCN

k = CCN.getDefaultKey()

private1_der = k.privateToDER()
public1_der = k.publicToDER()

k2 = Key()
k2.fromDER(private=private1_der)

private2_der = k2.privateToDER()
public2_der = k2.publicToDER()

assert(private1_der == private2_der)
assert(public1_der == public2_der)
assert(k.publicKeyID == k2.publicKeyID)

del(k2)

k2 = Key()
k2.fromDER(public=public1_der)

try:
	private2_der = k2.privateToDER()
except:
	pass
else:
	raise AssertionError("This should fail - this is not a private key")

public2_der = k2.publicToDER()

assert(public1_der == public2_der)
assert(k.publicKeyID == k2.publicKeyID)
