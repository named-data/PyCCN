from pyccn import CCN, _pyccn

handle = _pyccn.create()

#this should fail
try:
	_pyccn.disconnect(handle)
except _pyccn.CCNError:
	pass
else:
	raise AssertionError("Closing an unopened connection should fail")

_pyccn.connect(handle)
_pyccn.disconnect(handle)

try:
	_pyccn.disconnect(handle)
except _pyccn.CCNError:
	pass
else:
	raise AssertionError("Closing handle twice shouldn't work")

del handle

c = CCN()
_pyccn.disconnect(c.ccn_data)
del c
