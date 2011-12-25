#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#             Jeff Burke <jburke@ucla.edu>
#

# Front ccn_parsed_interest.
# Sort of.

#
#    //  IMPORTANT:  Exclusion component list must be sorted following "Canonical CCNx ordering"
#    //              http://www.ccnx.org/releases/latest/doc/technical/CanonicalOrder.html
#    //              in which shortest components go first.
#

from . import _pyccn
from . import Name

AOK_CS      = 0x1  # Answer from content store
AOK_NEW     = 0x2  # OK to produce new content
AOK_STALE   = 0x4  # OK to answer with stale data
AOK_EXPIRE  = 0x10 # Mark as stale (requires scope 0)

AOK_DEFAULT = AOK_CS | AOK_NEW

class Interest(object):
	def __init__(self, name=None, minSuffixComponents=None, \
				 maxSuffixComponents=None, publisherPublicKeyDigest=None, \
				 exclude=None, childSelector=None, answerOriginKind=None, \
				 scope=None, interestLifetime=None, nonce=None):

		self.name = name  # Start from None to use for templates?
		self.minSuffixComponents = minSuffixComponents  # default 0
		self.maxSuffixComponents = maxSuffixComponents  # default infinity
		self.publisherPublicKeyDigest = publisherPublicKeyDigest  # SHA256 hash
		self.exclude = exclude
		self.childSelector = childSelector
		self.answerOriginKind = answerOriginKind
		self.scope  = scope
		self.interestLifetime = interestLifetime
		self.nonce = nonce

		# pyccn
		self.ccn_data_dirty = True
		self.ccn_data = None  # backing charbuf

	def __setattr__(self, name, value):
		if name != "ccn_data_dirty":
			self.ccn_data_dirty = True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name == "ccn_data":
			# force refresh if components changed
			if object.__getattribute__(self, 'name') and self.name.ccn_data_dirty:
				self.ccn_data_dirty = True
			elif object.__getattribute__(self, 'exclude') and self.exclude.ccn_data_dirty:
				self.ccn_data_dirty = True

			if object.__getattribute__(self, 'ccn_data_dirty'):
				self.ccn_data = _pyccn.Interest_obj_to_ccn(self)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

	def __str__(self):
		res = []
		res.append("name: %s" % self.name)
		res.append("minSuffixComponents: %s" % self.minSuffixComponents)
		res.append("maxSuffixComponents: %s" % self.maxSuffixComponents)
		res.append("publisherPublicKeyDigest: %r" % self.publisherPublicKeyDigest)
		res.append("exclude:\n%s" % self.exclude)
		res.append("childSelector: %s" % self.childSelector)
		res.append("answerOriginKind: %s" % self.answerOriginKind)
		res.append("scope: %s" % self.scope)
		res.append("interestLifetime: %s" % self.interestLifetime)
		res.append("nonce: %r" % self.nonce)
		return "\n".join(res)

	def get_aok_value(self):
		global AOK_DEFAULT
		return AOK_DEFAULT if not self.answerOriginKind else self.answerOriginKind

	def matches_name(self, name):
		i_name = self.name.components
		o_name = name.components

		# requested name is longer than ours
		if len(i_name) > len(o_name):
			return False

		# at least one of given components don't match
		if not all(i == j for i, j in zip(i_name, o_name)):
			return False

		return True

# Bloom filters will be deprecated, so we do not support them.
class ExclusionFilter(object):
	def __init__(self):
		self.components = []
		# pyccn
		self.ccn_data_dirty = False
		self.ccn_data = None  # backing charbuf

	def reset(self):
		self.components = []

	def add_names(self, names):
		self.ccn_data_dirty = True
		self.components.extend(sorted(names))

	def add_name(self, name):
		if not type(name) is Name.Name:
			raise TypeError("Name type required")

		self.ccn_data_dirty = True
		self.components.append(name)

	def add_any(self):
		self.components.append(Name.Name(name_type=Name.NAME_ANY))

	def __setattr__(self, name, value):
		if name != "ccn_data_dirty":
			self.ccn_data_dirty = True
		object.__setattr__(self, name, value)

	def __getattribute__(self, name):
		if name == "ccn_data":
			if object.__getattribute__(self, 'ccn_data_dirty'):
				self.ccn_data = _pyccn.ExclusionFilter_names_to_ccn(
					self.components)
				self.ccn_data_dirty = False
		return object.__getattribute__(self, name)

	def __str__(self):
		comps = []
		for n in self.components:
			comps.append(str(n))
		return str(comps)
