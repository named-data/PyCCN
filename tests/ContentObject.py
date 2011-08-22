from pyccn import ContentObject, _pyccn

a = _pyccn.content_to_bytearray

assert(a("hello world") == b"hello world")

b = a(42)
c = bytearray(b"42")
assert(b == c)

assert(a(3.14) == b"3.14")
assert(a(int(3)) == b"3")
assert(a([65, 66, 67]) == b"ABC")

b = a("hi, how are you?")
c = a(b)
assert(b == c)
assert(a(None) == None)
