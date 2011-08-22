from pyccn import Key, Name, _pyccn

n = Name.Name()
n.setURI("/this/is/a/name")

ccn_name1 = n.ccn_data
name1 = _pyccn._pyccn_Name_from_ccn(ccn_name1)

locator1 = _pyccn._pyccn_KeyLocator_to_ccn(name=ccn_name1)
print(locator1)

ccn_name2 = _pyccn._pyccn_KeyLocator_from_ccn(locator1)
name2 = _pyccn._pyccn_Name_from_ccn(ccn_name2)
print(name2)

for comp1, comp2 in zip(name1, name2):
	if comp1 != comp2:
		raise AssertionError("Got a different output: '%s' != '%s'" % (comp1, comp2))

key1 = Key.Key()
key1.generateRSA(1024)

locator2 = _pyccn._pyccn_KeyLocator_to_ccn(key=key1.ccn_data_public)
print(locator2)

key2 = _pyccn._pyccn_KeyLocator_from_ccn(locator2)
print(key2)

print(key1.ccn_data_public)
print(key2.ccn_data_public)

#there's not an easy way to check if those two are equal
#I was hoping to modify the code so it would just output
#relevant info, but those rewritings just take too much time
