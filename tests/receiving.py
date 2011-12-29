import pyccn
from subprocess import Popen, PIPE
import threading
import sys

def arrgh(x):
	if sys.version_info.major >= 3:
		return bytes(x, "ascii")
	else:
		return bytes(x)

class sendMessage(threading.Thread):
	def run(self):
		po = Popen(['ccnput', '-x', '5', '-t', 'ENCR', 'ccnx:/messages/hello'], stdin=PIPE)
		po.communicate(arrgh("Hello everyone"))
#		po.stdin.close()
		po.wait()

thread = sendMessage()

name = pyccn.Name("ccnx:/messages/hello")
handle = pyccn.CCN()

thread.start()
co = handle.get(name)
thread.join()

print(co)
print(co.content)
print(type(co.content))

assert co.content == bytearray(b"Hello everyone")
print(co.name)
assert str(co.name) == "/messages/hello"

signedinfo = co.signedInfo
assert signedinfo.type == pyccn.CONTENT_ENCR

signature = co.signature

print(signedinfo)
