from pyccn import Key, _pyccn

key = Key.Key()
key.generateRSA(1024)

locator = Key.KeyLocator()
locator.key = key

ccn = _pyccn._pyccn_KeyLocator_to_ccn(locator)
