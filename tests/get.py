from pyccn import CCN, Name

c = CCN()
print(c)

n = Name()
print(n)

n = Name("ccnx:/ccnx/ping")
print(n)

co = c.get(n)
print(co)

#this shouldn't cause segfault
print(n)

n = Name("ccnx:/ccnx/some_nonexisting_name")
co = c.get(n, None, 100)

#this shouldn't cause segfault!
print(co)
