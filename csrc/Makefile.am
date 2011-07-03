#libdir=../lib
pyccndir=$(pythondir)/pyccn
pyccn_LTLIBRARIES = _pyccn.la
noinst_HEADERS = pyccn.h key_utils.h

_pyccn_la_SOURCES = pyccn.c key_utils.c
_pyccn_la_CPPFLAGS = @PYTHON_CPPFLAGS@ @CCN_INCLUDES@
_pyccn_la_LDFLAGS = -module @PYTHON_LDFLAGS@ @CCN_LDFLAGS@ @CCN_LIBS@ @OPENSSL_LIBS@
