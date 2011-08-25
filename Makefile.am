ACLOCAL_AMFLAGS = -I build-aux -I m4

SUBDIRS = csrc python . tests

checkdir = $(abs_top_builddir)/tests/install
tmp_checkdir = $(top_builddir)/tests/tmp

check-local:
	-mkdir $(tmp_checkdir)
	$(MAKE) $(AM_MAKEFLAGS) install-data DESTDIR=$(checkdir)

clean-local:
	-rm -rf $(tmp_checkdir)
	-rm -rf $(checkdir)
