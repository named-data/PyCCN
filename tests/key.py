from pyccn import Key, Name, _pyccn, CCN

n = Name("/this/is/a/name")

ccn_name1 = n.ccn_data
name1 = _pyccn.name_comps_from_ccn(ccn_name1)

locator1 = _pyccn.KeyLocator_to_ccn(name=ccn_name1)
print(locator1)

locator1_obj = _pyccn.KeyLocator_obj_from_ccn(locator1)
print(locator1_obj)
print(locator1_obj.keyName)

name2 = _pyccn.name_comps_from_ccn(locator1_obj.keyName.ccn_data)
print(name2)

for comp1, comp2 in zip(name1, name2):
	if comp1 != comp2:
		raise AssertionError("Got a different output: '%s' != '%s'" % (comp1, comp2))

key1 = CCN.getDefaultKey()

locator2 = _pyccn.KeyLocator_to_ccn(key=key1.ccn_data_public)
print(locator2)

locator2_obj = _pyccn.KeyLocator_obj_from_ccn(locator2)
key2 = locator2_obj.key
print(key2)

print(key1.ccn_data_public)
print(key2.ccn_data_public)

assert(key1.publicToDER() == key2.publicToDER())

del key2
key2 = _pyccn.Key_obj_from_ccn(key1.ccn_data_private)

assert(key1.publicKeyID == key2.publicKeyID)
assert(key1.publicToDER() == key2.publicToDER())
assert(key1.privateToDER() == key2.privateToDER())

del key2
key2 = _pyccn.Key_obj_from_ccn(key1.ccn_data_public)

assert(key1.publicKeyID == key2.publicKeyID)
assert(key1.publicToDER() == key2.publicToDER())
assert(key2.ccn_data_private == None)
