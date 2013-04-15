import pyccn
from pyccn import Name, NameCrypto, Key, KeyLocator, CCN

# Test symmetric authentication

state = NameCrypto.new_state()

secret = '1234567812345678'

app_name = 'cuerda'

app_key = NameCrypto.generate_application_key(secret, app_name)

name = Name('/ndn/ucla.edu/apps/cuerda')

auth_name = NameCrypto.authenticate_command(state, name, app_name, app_key)
print auth_name

window = -1

state2 = NameCrypto.new_state()

ret = NameCrypto.verify_command(state2, auth_name, window, fixture_key=secret)
print ret
assert(ret == True)

name_from_js = Name(
'/ndn/ucla.edu/apps/cuerda/%40%96%1CQ%00%06cuerdaQk%8A%13%00%07%B8%90%00%00%00%03%00%00%00%00%BB%14%FCHl%A5%F6%5D%18%1EIs%9E%91t%5El%C1y%3F%BAA%A7%02Y%EC%804%23%A4%D4t'
)

state3 = NameCrypto.new_state()

ret = NameCrypto.verify_command(state2, name_from_js, window, fixture_key=secret)
print ret
assert(ret == True)

# Test asymmetric authentication

state = NameCrypto.new_state()

name = Name('/ndn/ucla.edu/apps/cuerda')

key = CCN.getDefaultKey()

keyLoc = KeyLocator(key)
keyLocStr = pyccn._pyccn.dump_charbuf(keyLoc.ccn_data)

name = name.append(keyLocStr)

auth_name = NameCrypto.authenticate_command_sig(state, name, app_name, key)
print auth_name


keyLocStr2 = auth_name[-2]
capsule2 = pyccn._pyccn.new_charbuf('KeyLocator_ccn_data', keyLocStr2)
keyLoc2 = pyccn._pyccn.KeyLocator_obj_from_ccn(capsule2)

state2 = NameCrypto.new_state()

ret = NameCrypto.verify_command(state2, auth_name, window, pub_key=keyLoc2.key)
print ret
assert(ret == True)

name_from_js2 = Name(
'/ndn/ucla.edu/apps/cuerda/%01%E2%01%DA%0A%950%81%9F0%0D%06%09%2A%86H%86%F7%0D%01%01%01%05%00%03%81%8D%000%81%89%02%81%81%00%E1%7D0%A7%D8%28%AB%1B%84%0B%17T-%CA%F6%20z%FD%22%1E%08k%2A%60%D1l%B7%F5DH%BA%9F%3F%08%BC%D0%99%DB%21%DD%16%2Aw%9Ea%AA%89%EE%E5T%D3%A4%7D%E20%BCz%C5%90%D5%24%06%7C8%98%BB%A6%F5%DCC%60%B8E%ED%A4%8C%BD%9C%F1%26%A7%23D_%0E%19R%D72Zu%FA%F5V%14O%9A%98%AFq%86%B0%27%86%85%B8%E2%C0%8B%EA%87%17%1BM%EEX%5C%18%28%29%5BS%95%EBJ%17w%9F%02%03%01%00%01%00%00/%21D%07e%00%06cuerdaQk%8A%13%00%07V%E8%00%00%00%02%00%00%00%00%27%B3%26g%E9%DA%5B%5B%FE%E9%9B%96%C00%CF%DFUc%B4%C9%29%0E%82Kps%CA%E9%B9%21.%06b%AF%C7W%1Fh%1F%8D%A9%9AXf%7F%00%7FZa%9A%1C%B4u8%7C%0F%28%242v%A7%98%9F%18%C3%18%25%B7%E4%EC%1F%21%ED%FA%93F%89%3E%9CE%E8%FE%19H%03%B79%7D%2Ajg%DB%1C%D6e%A4X%E1%9Dn5%C3%00%3AO%EDc%CCE%2A%E6%2A%9F%09%7D%A2p%B0%82%7F%E7%A5%CFb%EA%DF%89%F7'
)

keyLocStr3 = name_from_js2[-2]
capsule3 = pyccn._pyccn.new_charbuf('KeyLocator_ccn_data', keyLocStr3)
keyLoc3 = pyccn._pyccn.KeyLocator_obj_from_ccn(capsule3)

state3 = NameCrypto.new_state()

ret = NameCrypto.verify_command(state3, name_from_js2, window, pub_key=keyLoc3.key)
print ret
assert(ret == True)

