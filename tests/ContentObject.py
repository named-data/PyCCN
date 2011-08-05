from pyccn import ContentObject, _pyccn

a = _pyccn.content_to_bytearray

assert(a("hello world") == b"hello world")
assert(a(42) == b"42")
assert(a(3.14) == b"3.14")
assert(a(long(3)) == b"3")
assert(a(['a', 'b', 'c']) == b"abc")

b = a("hi, how are you")
c = a(b)
assert(b == c)
assert(a(None) == None)

