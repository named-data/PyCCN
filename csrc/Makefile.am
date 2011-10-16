pyccndir = $(PYTHON_SITE_PKG)/pyccn

pyccn_LTLIBRARIES = _pyccn.la
noinst_HEADERS = \
	pyccn.h \
	key_utils.h \
	methods.h \
	methods_contentobject.h \
	methods_handle.h \
	methods_interest.h \
	methods_key.h \
	methods_name.h \
	methods_signature.h \
	methods_signedinfo.h \
	objects.h \
	python_hdr.h \
	util.h

_pyccn_la_SOURCES = \
	pyccn.c \
	key_utils.c \
	methods.c \
	methods_contentobject.c \
	methods_handle.c \
	methods_interest.c \
	methods_key.c \
	methods_name.c \
	methods_signature.c \
	methods_signedinfo.c \
	objects.c \
	util.c


noinst_HEADERS += methods_namecrypto.h
_pyccn_la_SOURCES += methods_namecrypto.c \
	namecrypto/authentication.c \
	namecrypto/encryption.c \
	namecrypto/toolkit.c

#_pyccn_la_SOURCES += $(noinst_HEADERS:.h=.h.gch)

#-O3 -pedantic -Wall -Wextra -fdiagnostics-show-option -Winvalid-pch
#-Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wconversion -Werror
_pyccn_la_CPPFLAGS = -std=c99 -Wall -Wextra -Winvalid-pch -Wstrict-prototypes
_pyccn_la_CPPFLAGS += -Wmissing-prototypes -Wshadow -fdiagnostics-show-option
_pyccn_la_CPPFLAGS += @PYTHON_CPPFLAGS@ @CCN_INCLUDES@ @OPENSSL_INCLUDES@ -Wno-unknown-pragmas
_pyccn_la_LDFLAGS = -avoid-version -module @PYTHON_LDFLAGS@ \
	@CCN_LDFLAGS@ @OPENSSL_LDFLAGS@ @CCN_LIBS@ @OPENSSL_LIBS@

.h.h.gch:
	$(CC) -c $<

SUFFIXES = .h .h.gch
