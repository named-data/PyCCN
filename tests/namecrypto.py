import pyccn
from pyccn import Name, NameCrypto, Key, KeyLocator, CCN

window = -1

# Test symmetric authentication

state = NameCrypto.new_state()

secret = '1234567812345678'

app_name = 'cuerda'

app_key = NameCrypto.generate_application_key(secret, app_name)

name = Name('/ndn/ucla.edu/apps/cuerda')

auth_name = NameCrypto.authenticate_command(state, name, app_name, app_key)
print auth_name

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

state2 = NameCrypto.new_state()

ret = NameCrypto.verify_command(state2, auth_name, window, pub_key=key)
print ret
#assert(ret == True)

name_from_js2 = Name(
'/ndn/ucla.edu/apps/cuerda/%01%E2%01%DA%0A%950%81%9F0%0D%06%09%2A%86H%86%F7%0D%01%01%01%05%00%03%81%8D%000%81%89%02%81%81%00%E1%7D0%A7%D8%28%AB%1B%84%0B%17T-%CA%F6%20z%FD%22%1E%08k%2A%60%D1l%B7%F5DH%BA%9F%3F%08%BC%D0%99%DB%21%DD%16%2Aw%9Ea%AA%89%EE%E5T%D3%A4%7D%E20%BCz%C5%90%D5%24%06%7C8%98%BB%A6%F5%DCC%60%B8E%ED%A4%8C%BD%9C%F1%26%A7%23D_%0E%19R%D72Zu%FA%F5V%14O%9A%98%AFq%86%B0%27%86%85%B8%E2%C0%8B%EA%87%17%1BM%EEX%5C%18%28%29%5BS%95%EBJ%17w%9F%02%03%01%00%01%00%00/%21D%07e%00%06cuerdaQk%90%CF%00%050%20%00%00%00%01%00%00%00%007%11%03%A1%0BS6%FF%CD%EA%5B%94%1B%9F%D8%1F0F%C0%A0%EA%CE%19%02%1D%E0k4%F0%E1%28%A1%881%BE%8F%60%95%9F%FB%21%04%D0%5C%90%EA%BC%0C%25%D1%05%CF%E8%1E%FB%A8%2AVp%BF%7B%06%07%C5Cs%A4%BB%B01%03%5D%8A%8EI%AA.%AA%9Cs%1F%DF%FE%C3%D5%BC%E5%DEL_%BF%EEj%D9G%E9%AC%EC%C69%5C%18%AE%A5%F3uv%91E%A4cM%EE%9B%F1+%26%C4%B3JsFk+%C5%3EP%2F'
)

keyLocStr2 = name_from_js2[-2]
capsule = pyccn._pyccn.new_charbuf('KeyLocator_ccn_data', keyLocStr2)
keyLoc2 = pyccn._pyccn.KeyLocator_obj_from_ccn(capsule)

state3 = NameCrypto.new_state()

ret = NameCrypto.verify_command(state3, name_from_js2, window, pub_key=keyLoc2.key)
print ret
#assert(ret == True)

