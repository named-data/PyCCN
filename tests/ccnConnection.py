from pyccn import CCN, _pyccn

handle = _pyccn._pyccn_ccn_create()

#this should fail
try:
	_pyccn._pyccn_ccn_disconnect(handle)
except _pyccn.CCNError:
	pass
else:
	raise AssertionError("Closing an unopened connection should fail")

_pyccn._pyccn_ccn_connect(handle)
_pyccn._pyccn_ccn_disconnect(handle)

try:
	_pyccn._pyccn_ccn_disconnect(handle)
except _pyccn.CCNError:
	pass
else:
	raise AssertionError("Closing handle twice shouldn't work")

del handle

c = CCN.CCN()
_pyccn._pyccn_ccn_disconnect(c.ccn_data)
del c
