#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#

class Flag(int):
	__initialized = False
	_flags = None
	__flags_values__ = None

	@classmethod
	def initialize(cls):
		cls._flags = {}
		cls.__flags_values__ = {}
		cls.__initialized = True

	@classmethod
	def new_flag(cls, name, value):
		if not cls.__initialized:
			cls.initialize()

		cls._flags[value] = name

		obj = cls(value)
		cls.__flags_values__[value] = obj

		return obj

	def __new__(cls, value):
		if cls.__flags_values__.has_key(value):
			return cls.__flags_values__[value]

		return super(Flag, cls).__new__(cls, value)

	def generate_repr(self):
		val = long(self)
		flags = [name for i, name in self._flags.items() if i & val]
		return " | ".join(flags)

	def __repr__(self):
		t = type(self)
		type_name = "%s.%s" % (t.__module__, t.__name__)
		return "<flags %s of type %s>" % (self.generate_repr(), type_name)

	def __and__(self, other):
		cls = type(self)
		return cls(long(self) & long(other))

	def __xor__(self, other):
		cls = type(self)
		return cls(long(self) ^ long(other))

	def __or__(self, other):
		cls = type(self)
		return cls(long(self) | long(other))

class Enum(Flag):
	def __new__(cls, value):
		if cls.__flags_values__.has_key(value):
			return cls.__flags_values__[value]

		if cls._flags.has_key(value):
			return super(Enum, cls).__new__(cls, value)

		raise ValueError("invalid flag value: %d" % value)

	def generate_repr(self):
		return self._flags[long(self)]
