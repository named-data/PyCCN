import sys
from pyccn import CCN, Name, Interest, Closure

def usage():
	print("Usage: %s <URI> <timeout>" % sys.argv[0])
	sys.exit(1)

if (len(sys.argv) != 3):
	usage()

root = sys.argv[1]
timeout = int(sys.argv[2])

class Slurp(Closure.Closure):
	def __init__(self, root, timeout):
		self.root = Name.Name(root)
		self.timeout = timeout
		self.handle = CCN.CCN()
		self.exclusions = Interest.ExclusionFilter()

	def start(self):
		self.exclusions.reset()
		self.handle.expressInterest(self.root, self)
		self.handle.run(self.timeout)

	def upcall(self, kind, upcallInfo):
		#print("upcall called; kind %d" % kind)

		if kind == Closure.UPCALL_FINAL:
			#any cleanup code here (probably not needed)
			return Closure.UPCALL_RESULT_OK

		if kind == Closure.UPCALL_INTEREST_TIMED_OUT:
			print("Got timeout!")
			return Closure.UPCALL_RESULT_OK

		# make sure we're getting sane responses
		if not kind in [Closure.UPCALL_CONTENT,
						Closure.UPCALL_CONTENT_UNVERIFIED,
						Closure.UPCALL_CONTENT_BAD]:
			print("Received invalid kind type %d" % kind)
			sys.exit(100)

		matched_comps = upcallInfo.matchedComps
		response_name = upcallInfo.ContentObject.name
		org_prefix = Name.Name(response_name.components[:matched_comps])
		comp = Name.Name(response_name.components[matched_comps:])

		if kind == Closure.UPCALL_CONTENT_BAD:
			print("*** VERIFICATION FAILURE *** %s" % response_name)

		print("ccnx:%s [%s]" % (response_name, "verified" if kind == Closure.UPCALL_CONTENT else "unverified"))

		templ = Interest.Interest()
		templ.name = org_prefix
		templ.exclude = self.exclusions
		templ.exclude.add_name(comp)

		self.handle.expressInterest(org_prefix, self, templ)

		return Closure.UPCALL_RESULT_OK

print("Scanning %s, timeout=%dms" % (root, timeout))
slurp = Slurp(root, timeout)
slurp.start()
