AC_DEFUN([AX_CHECK_CCN], [
	AX_CHECK_OPENSSL(,AC_MSG_ERROR([CCNx requires OpenSSL]))

	ccndirs="/usr/local /usr $HOME/ccnx"
	AC_ARG_WITH([ccn],
		[AS_HELP_STRING([--with-ccn=DIR],
			[root of the CCN directory])],
		[
			case "$withval" in
			"" | y | ye | yes | n | no)
				AC_MSG_ERROR([Invalid --with-ccn value])
				;;
			*)
				ccndirs="$withval"
				;;
			esac
		], [
			AC_MSG_WARN([No --with-ccn provided, trying to detect])
		])

	for ccndir in $ccndirs; do
		AC_MSG_CHECKING([for include/ccn/ccn.h in $ccndir])
		if test -f "$ccndir/include/ccn/ccn.h"; then
			CCN_INCLUDES="-I$ccndir/include"
			CCN_LDFLAGS="-L$ccndir/lib"
			CCN_LIBS="-lccn"
			CCN_BIN="$ccndir/bin"
			AC_MSG_RESULT([yes])
			break
		else
			AC_MSG_RESULT([no])
		fi
	done

	AC_MSG_CHECKING([whether compiling and linking against CCNx works])

	save_LIBS="$LIBS"
	save_CPPFLAGS="$CPPFLAGS"
	save_LDFLAGS="$LDFLAGS"

	LIBS="$LIBS $CCN_LIBS $OPENSSL_LIBS"
	CPPFLAGS="$CCN_INCLUDES $CPPFLAGS"
	LDFLAGS="$CCN_LDFLAGS $OPENSSL_LDFLAGS $LDFLAGS"

	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM([#include <ccn/ccn.h>], [ccn_create()])],
		[
			AC_MSG_RESULT([yes])
			$1
		], [
			AC_MSG_RESULT([no])
			$2
		])

	LIBS="$save_LIBS"
	CPPFLAGS="$save_CPPFLAGS"
	LDFLAGS="$save_LDFLAGS"

	AC_MSG_CHECKING([whether $CCN_BIN is a valid executable path])
	if test -x "$CCN_BIN/ccnput"; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Unable to find ccnput in $CCN_BIN])
	fi

	AC_SUBST([CCN_INCLUDES])
	AC_SUBST([CCN_LDFLAGS])
	AC_SUBST([CCN_LIBS])
	AC_SUBST([CCN_BIN])
])
