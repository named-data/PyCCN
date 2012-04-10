import pyccn.utils as utils

class Test1(utils.Enum):
	pass

VAL1 = Test1.new_flag('VAL1', 1)
VAL2 = Test1.new_flag('VAL2', 2)
VAL3 = Test1.new_flag('VAL3', 3)

print "%r %r %r" % (VAL1, VAL2, VAL3)
assert VAL1 == 1
assert repr(VAL1) == '<flags VAL1 of type __main__.Test1>'
assert VAL2 == 2
assert repr(VAL2) == '<flags VAL2 of type __main__.Test1>'
assert VAL3 == 3
assert repr(VAL3) == '<flags VAL3 of type __main__.Test1>'

class Test2(utils.Flag):
	pass

FLAG1 = Test2.new_flag('FLAG1', 4)
FLAG2 = Test2.new_flag('FLAG2', 2)
FLAG3 = Test2.new_flag('FLAG3', 16)

print "%r %r %r" % (FLAG1, FLAG2, FLAG3)
assert FLAG1 == 4
assert repr(FLAG1) == '<flags FLAG1 of type __main__.Test2>'
assert FLAG2 == 2
assert repr(FLAG2) == '<flags FLAG2 of type __main__.Test2>'
assert FLAG3 == 16
assert repr(FLAG3) == '<flags FLAG3 of type __main__.Test2>'

FLAG123 = FLAG1 | FLAG2 | FLAG3
assert FLAG123 == 22
assert repr(FLAG123) == '<flags FLAG3 | FLAG2 | FLAG1 of type __main__.Test2>', repr(FLAG123)

FLAG23 = FLAG123 ^ FLAG1
assert FLAG23 == 18
assert repr(FLAG23) == '<flags FLAG3 | FLAG2 of type __main__.Test2>', repr(FLAG23)

FLAG2_ = FLAG123 & FLAG2
assert FLAG2_ == 2
assert repr(FLAG2_) == '<flags FLAG2 of type __main__.Test2>', repr(FLAG2_)

print "%r %r %r" % (VAL1, VAL2, VAL3)
assert VAL1 == 1
assert repr(VAL1) == '<flags VAL1 of type __main__.Test1>'
assert VAL2 == 2
assert repr(VAL2) == '<flags VAL2 of type __main__.Test1>'
assert VAL3 == 3
assert repr(VAL3) == '<flags VAL3 of type __main__.Test1>'

class ContentType(utils.Enum):
	pass

CONTENT_DATA = ContentType.new_flag('CONTENT_DATA', 0x0C04C0)
CONTENT_ENCR = ContentType.new_flag('CONTENT_ENCR', 0x10D091)
CONTENT_GONE = ContentType.new_flag('CONTENT_GONE', 0x18E344)
CONTENT_KEY = ContentType.new_flag('CONTENT_KEY', 0x28463F)
CONTENT_LINK = ContentType.new_flag('CONTENT_LINK', 0x2C834A)
CONTENT_NACK = ContentType.new_flag('CONTENT_NACK', 0x34008A)

assert ContentType(0x28463F) == CONTENT_KEY

