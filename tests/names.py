from pyccn import CCN, Name

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
