#libdir=../lib
pyccndir=$(pythondir)/pyccn
pyccn_LTLIBRARIES = _pyccn.la
noinst_HEADERS = pyccn.h key_utils.h misc.h converters.h methods.h

_pyccn_la_SOURCES = pyccn.c key_utils.c misc.c converters.c methods.c
_pyccn_la_CPPFLAGS = -Wall @PYTHON_CPPFLAGS@ @CCN_INCLUDES@
_pyccn_la_LDFLAGS = -module @PYTHON_LDFLAGS@ @CCN_LDFLAGS@ @CCN_LIBS@ @OPENSSL_LIBS@
