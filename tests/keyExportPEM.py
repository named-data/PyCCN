import os, filecmp
from base64 import b64encode, b64decode
from pyccn import Key, _pyccn, CCN

print(os.getcwd())

root = os.path.join("tmp")
private_pem1 = os.path.join(root, 'private1.pem')
public_pem1 = os.path.join(root, 'public1.pem')
private_pem2 = os.path.join(root, 'private2.pem')
public_pem2 = os.path.join(root, 'public2.pem')

def rm_files(*list):
	for file in list:
		if os.path.exists(file):
			os.remove(file)

rm_files(private_pem1, public_pem1, private_pem2, public_pem2)

k = CCN.getDefaultKey()

k.privateToPEM(filename=private_pem1)
k.publicToPEM(filename=public_pem1)

k2 = Key()
k2.fromPEM(filename=private_pem1)

k2.privateToPEM(filename=private_pem2)
k2.publicToPEM(filename=public_pem2)

assert(filecmp.cmp(private_pem1, private_pem2))
assert(filecmp.cmp(public_pem1, public_pem2))
print(b64encode(k.publicKeyID))
print(b64encode(k2.publicKeyID))
assert(k.publicKeyID == k2.publicKeyID)

del(k2)
rm_files(private_pem2, public_pem2)

k2 = Key()
k2.fromPEM(filename=public_pem1)

try:
	k2.privateToPEM(filename=private_pem2)
except:
	pass
else:
	raise AssertionError("This should fail - this is not a private key")

k2.publicToPEM(filename=public_pem2)

assert(filecmp.cmp(public_pem1, public_pem2))
assert(k.publicKeyID == k2.publicKeyID)

rm_files(private_pem1, public_pem1, private_pem2, public_pem2)

private = k.privateToPEM()
public = k.publicToPEM()

k2 = Key()
k2.fromPEM(private=private)

assert(k.privateToDER() == k2.privateToDER())
assert(k.publicToDER() == k2.publicToDER())
assert(k.publicKeyID == k2.publicKeyID)

k2 = Key()
k2.fromPEM(public=public)

try:
	k2.privateToPEM()
except:
	pass
else:
	raise AssertionError("This should fail - this is not a private key")

assert(k.publicToDER() == k2.publicToDER())
assert(k.publicKeyID == k2.publicKeyID)
