AC_DEFUN([AX_CCN_OPENSSL], [
dnl	AC_ARG_WITH([openssl],
dnl		[AS_HELP_STRING([--with-openssl=DIR],
dnl			[root of the OpenSSL directory])],
dnl		[   
dnl			case "$withval" in
dnl			"" | y | ye | yes | n | no)
dnl			AC_MSG_ERROR([Invalid --with-openssl value])
dnl				;;
dnl			*) ssldir="$withval"
dnl				;;
dnl			esac
dnl		],[])

	AC_MSG_CHECKING([for libcrypto used with ccnd])
	if test -n "$OTOOL" ; then
		libcrypto=$(OTOOL -L "$1" | $FGREP libcrypto | $AWK '{print $[]1}')
	fi

	module=no
	eval libcrypto_ext=$shrext_cmds
	libcrypto_ver=$(expr //${libcrypto} : '.*/libcrypto\.\(.*\)'${libcrypto_ext})

	AC_MSG_RESULT([$libcrypto (version: $libcrypto_ver)])

	ssldir=$(dirname $(dirname "$libcrypto"))
	OPENSSL_INCLUDES="-I$ssldir/include"
	OPENSSL_LIBS="-lcrypto.$libcrypto_ver"
	OPENSSL_LDFLAGS="-L$ssldir/lib"

	AC_MSG_RESULT([Detected settings:])
	AC_MSG_RESULT([ INCLUDES = $OPENSSL_INCLUDES])
	AC_MSG_RESULT([ LIBS     = $OPENSSL_LIBS])
	AC_MSG_RESULT([ LDFLAGS  = $OPENSSL_LDFLAGS])

	AC_MSG_CHECKING([whether compiling and linking against OpenSSL works])

	echo "Trying link with OPENSSL_LDFLAGS=$OPENSSL_LDFLAGS;" \
		"OPENSSL_LIBS=$OPENSSL_LIBS; OPENSSL_INCLUDES=$OPENSSL_INCLUDES" >&AS_MESSAGE_LOG_FD

	save_LIBS="$LIBS"
	save_LDFLAGS="$LDFLAGS"
	save_CPPFLAGS="$CPPFLAGS"
	LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
	LIBS="$OPENSSL_LIBS $LIBS"
	CPPFLAGS="$OPENSSL_INCLUDES $CPPFLAGS"
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM([#include <openssl/ssl.h>], [EVP_PKEY_new()])],
		[
			AC_MSG_RESULT([yes])
			$2
		], [
			AC_MSG_RESULT([no])
			$3
		])
	CPPFLAGS="$save_CPPFLAGS"
	LIBS="$save_LIBS"
	LDFLAGS="$save_LDFLAGS"

	AC_SUBST([OPENSSL_INCLUDES])
	AC_SUBST([OPENSSL_LIBS])
	AC_SUBST([OPENSSL_LDFLAGS])
])

AC_DEFUN([AX_CHECK_CCN], [
dnl	AX_CHECK_OPENSSL(,AC_MSG_ERROR([CCNx requires OpenSSL]))

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

	AC_MSG_CHECKING([whether $CCN_BIN is a valid executable path])
	if test -x "$CCN_BIN/ccnd"; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Unable to find ccnd in $CCN_BIN])
	fi

	AX_CCN_OPENSSL($CCN_BIN/ccnd,,AC_MSG_ERROR([Unable to determine OpenSSL location]))
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

	AC_SUBST([CCN_INCLUDES])
	AC_SUBST([CCN_LDFLAGS])
	AC_SUBST([CCN_LIBS])
	AC_SUBST([CCN_BIN])
])
