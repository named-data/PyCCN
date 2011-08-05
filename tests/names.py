from pyccn import _pyccn, CCN, Name
import sys

comps = ['this', 'is', 'some', 'potential', 'name']
print comps

ccn_name = _pyccn._pyccn_Name_to_ccn(comps)
comps2 = _pyccn._pyccn_Name_from_ccn(ccn_name)
print comps2

for comp1, comp2 in zip(map(lambda x: bytearray(x), comps), comps2):
	if comp1 != comp2:
		raise AssertionError("Got a different output: '%s' != '%s'" % (comp1, comp2))

n = Name.Name(['hello', 'world'])

if str(n) != "/hello/world":
	raise AssertionError("expected /hello/world")

n.setURI("ccnx://testing/1/2/3/")
if str(n) != "/testing/1/2/3":
	raise AssertionError("expected /testing/1/2/3 got: " + str(n))

if len(n) != 4:
	raise AssertionError("expected 4 components, got: " + len(n))

if (n.components != ['testing', '1', '2', '3']):
	raise AssertionError("expected to get a list containing: testing, 1, 2, 3")
