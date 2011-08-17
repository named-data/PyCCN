from pyccn import CCN, Name
from subprocess import Popen, PIPE
import threading

class sendMessage(threading.Thread):
	def run(self):
		po = Popen(['ccnput', '-x', '5', 'ccnx:/messages/hello'], stdin=PIPE)
		po.stdin.writelines("Hello everyone")
		po.stdin.close()
		po.wait()

thread = sendMessage()

name = Name.Name("ccnx:/messages/hello")
handle = CCN.CCN()

thread.start()
co = handle.get(name)
thread.join()
#print co

assert co.content == "Hello everyone"
assert str(co.name) == "/messages/hello"

signedinfo = co.signedInfo
signature = co.signature

print signedinfo
