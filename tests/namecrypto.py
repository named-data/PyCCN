from pyccn import Name, NameCrypto

state = NameCrypto.new_state()

secret = '1234567812345678'

app_name = 'cuerda'

app_key = NameCrypto.generate_application_key(secret, app_name)

name = pyccn.Name('/ndn/ucla.edu/apps/cuerda')

auth_name = NameCrypto.authenticate_command(state, name, app_name, app_key)
print auth_name

window = -1

#print NameCrypto.verify_name_symm(auth_name, secret, window, app_name)

