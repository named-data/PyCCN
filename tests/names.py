from pyccn import _pyccn, CCN, Name
import sys

comps = ['this', 'is', 'some', 'name']
print(comps)

ccn_name = _pyccn.name_comps_to_ccn(comps)
comps2 = _pyccn.name_comps_from_ccn(ccn_name)
print(comps2)

#for comp1, comp2 in zip(map(lambda x: bytearray(x), comps), comps2):
for comp1, comp2 in zip([bytearray(x, "ascii") for x in comps], comps2):
	if comp1 != comp2:
		raise AssertionError("Got a different output: '%s' != '%s'" % (comp1, comp2))

n = Name.Name(['hello', 'world'])

print(str(n))
if str(n) != "/hello/world":
	raise AssertionError("expected /hello/world")

n.setURI("ccnx:///testing/1/2/3/")
print(str(n))
if str(n) != "/testing/1/2/3":
	raise AssertionError("expected /testing/1/2/3 got: " + str(n))

if len(n) != 4:
	raise AssertionError("expected 4 components, got: " + len(n))

print(n.components)
assert(n.components == [b'testing', b'1', b'2', b'3'])

n.components = [1, '2', bytearray(b'3'), bytes(b'4')]
print(str(n))
assert(str(n) == "/1/2/3/4")

n = Name.Name()
print(str(n))
n.appendSegment(5)
print(str(n))

assert(str(n) == "/%00%05")

