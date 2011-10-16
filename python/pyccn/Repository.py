from pyccn import Closure, Interest, Name

class RepoUpload(Closure.Closure):
	def __init__(self, handle, name, content):
		self.handle = handle
		self.name = Name.Name(name)
		self.content_objects = content

	def start(self):
		self.handle.setInterestFilter(self.name, self)

		interest = Interest.Interest(
			name = Name.Name(self.name))
		interest.name += '\xC1.R.sw'
		interest.name.appendNonce()

		print("Expressing interest: ccnx:%s" % interest.name)

		self.handle.expressInterest(interest.name, self, interest)
		self.handle.run(-1)

	def dispatch_content(self, interest, elem):
		if elem.matchesInterest(interest):
			print("serving: %s" % elem.name)
			self.handle.put(elem)
			return True
		return False

	def handle_interest(self, matched_comps, interest):
		f = lambda elem: self.dispatch_content(interest, elem)

		print("Received interest for: %s" % interest.name)

		consumed = False
		for i, elem in enumerate(self.content_objects):
			if f(elem):
				self.content_objects.pop(i)
				consumed = True
				break

		if len(self.content_objects) == 0:
			self.handle.setRunTimeout(0)

		return consumed

	def upcall(self, kind, info):
		if kind == Closure.UPCALL_FINAL:
			return Closure.RESULT_OK

		if kind == Closure.UPCALL_INTEREST:
			if self.handle_interest(info.matchedComps, info.Interest):
				return Closure.RESULT_INTEREST_CONSUMED
			else:
				return Closure.RESULT_OK

		print("- - - - -")
		print("kind: %d" % kind)
		print("name: %s" % info.Interest.name)
		return Closure.RESULT_OK

