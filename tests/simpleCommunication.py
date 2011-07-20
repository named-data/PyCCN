from pyccn import CCN,Name,Interest,ContentObject,Key

c = CCN.CCN()

#k = Key.Key()
#k.generateRSA(1024)

#kl = Key.KeyLocator()
#kl.key = k

n = Name.Name(["Foo", "Foo"])
i = Interest.Interest()
co = c.get(n, i, 50)

#co = ContentObject.ContentObject()
#co.name = n
#co.content = "Frou"

#si = ContentObject.SignedInfo()
#si.publisherPublicKeyDigest = k.publicKeyID
#si.type = 0x0C04C0
#si.freshness = -1

#co.signedInfo = si
#co.sign(k)
#c.put(co)
