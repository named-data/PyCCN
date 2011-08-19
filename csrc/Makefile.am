pyccndir = $(pythondir)/pyccn

pyccn_LTLIBRARIES = _pyccn.la
noinst_HEADERS = \
	pyccn.h \
	key_utils.h \
	methods.h \
	methods_contentobject.h \
	methods_interest.h \
	methods_key.h \
	methods_name.h \
	methods_signature.h \
	methods_signedinfo.h \
	objects.h \
	util.h

_pyccn_la_SOURCES = \
	pyccn.c \
	key_utils.c \
	methods.c \
	methods_contentobject.c \
	methods_interest.c \
	methods_key.c \
	methods_name.c \
	methods_signature.c \
	methods_signedinfo.c \
	objects.c \
	util.c

_pyccn_la_CFLAGS = -std=c99 -pedantic -O3 -ggdb3 -Wall -Wextra \
	-Wswitch-default -Wswitch-enum -Wfloat-equal
_pyccn_la_CPPFLAGS = @PYTHON_CPPFLAGS@ @CCN_INCLUDES@
_pyccn_la_LDFLAGS = -avoid-version -module @PYTHON_LDFLAGS@ \
	@CCN_LDFLAGS@ @CCN_LIBS@ @OPENSSL_LIBS@
