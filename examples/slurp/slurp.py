#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#

import sys
from pyccn import CCN, Name, Interest, Closure

class Slurp(Closure.Closure):
	def __init__(self, root, handle=None):
		self.root = Name.Name(root)
		self.exclusions = Interest.ExclusionFilter()
		self.handle = handle if handle else CCN.CCN()

	def start(self, timeout):
		self.exclusions.reset()
		self.express_my_interest()
		self.handle.run(timeout)

	def express_my_interest(self):
		templ = Interest.Interest(exclude=self.exclusions)
		self.handle.expressInterest(self.root, self, templ)

	def upcall(self, kind, upcallInfo):
		if kind == Closure.UPCALL_FINAL:
			#any cleanup code here (probably not needed)
			return Closure.RESULT_OK

		if kind == Closure.UPCALL_INTEREST_TIMED_OUT:
			print("Got timeout!")
			return Closure.RESULT_OK

		# make sure we're getting sane responses
		if not kind in [Closure.UPCALL_CONTENT,
						Closure.UPCALL_CONTENT_UNVERIFIED,
						Closure.UPCALL_CONTENT_BAD]:
			print("Received invalid kind type: %d" % kind)
			sys.exit(100)

		matched_comps = upcallInfo.matchedComps
		response_name = upcallInfo.ContentObject.name
		org_prefix = response_name[:matched_comps]

		assert(org_prefix == self.root)

		if matched_comps == len(response_name):
			comp = Name.Name([upcallInfo.ContentObject.digest()])
			disp_name = Name.Name(response_name)
		else:
			comp = response_name[matched_comps:matched_comps + 1]
			disp_name = response_name[:matched_comps + 1]

		if kind == Closure.UPCALL_CONTENT_BAD:
			print("*** VERIFICATION FAILURE *** %s" % response_name)

		print("%s [%s]" % (disp_name, \
			"verified" if kind == Closure.UPCALL_CONTENT else "unverified"))

		self.exclusions.add_name(comp)
		self.express_my_interest()

		# explore next level
		if matched_comps + 1 < len(response_name):
			new = Slurp(response_name[:matched_comps + 1], self.handle)
			new.express_my_interest()

		return Closure.RESULT_OK

def usage():
	print("Usage: %s <URI> <timeout>" % sys.argv[0])
	sys.exit(1)

if __name__ == '__main__':
	if (len(sys.argv) != 3):
		usage()

	root = sys.argv[1]
	timeout = int(sys.argv[2])

	print("Scanning %s, timeout=%dms" % (root, timeout))
	slurp = Slurp(root)
	slurp.start(timeout)
