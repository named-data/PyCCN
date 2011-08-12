ACLOCAL_AMFLAGS = -I build-aux -I m4

SUBDIRS = csrc python . tests

checkdir = $(abs_top_builddir)/tests/install

check-local:
	$(MAKE) $(AM_MAKEFLAGS) install-data DESTDIR=$(checkdir)

clean-local:
	-rm -rf $(checkdir)
