from pyccn import CCN, Name, Interest, Closure
from time import sleep
import thread

worked = False

class MyClosure(Closure.Closure):
	def upcall(self, kind, upcallInfo):
		global worked

		print "Got response"
		print kind
		print upcallInfo
		worked = True

n = Name.Name()
n.setURI("ccnx:/ccnx/ping")

i = Interest.Interest()
closure = MyClosure()

c = CCN.CCN()
res = c.expressInterest(n, closure, i)
print res

#causes crashes
c.run(10)
print "Ha!"
assert(worked)
