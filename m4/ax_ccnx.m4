#
# Copyright (c) 2012, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#

AC_DEFUN([AX_CCN_OPENSSL], [
	AC_ARG_VAR([OPENSSL_CRYPTO], [The full path to OpenSSL crypto library
		that CCNx is linked with, for example /usr/lib/libcrypto.so.1.0.0])
	AC_ARG_VAR([OPENSSL_INCLUDES], [The CFLAGS entry that includes path of
		OpenSSL headers, for example -I/usr/local/include])
	AC_ARG_VAR([OPENSSL_LDFLAGS], [The LDFLAGS entry that includes path of
		OpenSSL library, for example -L/usr/local/lib])

	#
	# Tools necessary for detecting which crypto library ccnd was linked with
	#
	AC_CHECK_TOOL([LDD], [ldd])
	AC_CHECK_TOOL([OTOOL], [otool])
	AC_PROG_AWK
	AC_PROG_FGREP

	#
	# Detecting OpenSSL's libcrypto that is linked with ccnd
	#
	AC_MSG_CHECKING([for libcrypto used with ccnd])

	if test -z "$OPENSSL_CRYPTO"; then
		if test -n "$LDD"; then
			OPENSSL_CRYPTO=$($LDD "$1" | $FGREP libcrypto | $AWK '{print $[]3}')
		elif test -n "$OTOOL" ; then
			OPENSSL_CRYPTO=$($OTOOL -L "$1" | $FGREP libcrypto | $AWK '{print $[]1}')
		else
			AC_MSG_ERROR([No ldd or otool available. Please specify OpenSSL crypto
				library manually using OPENSSL_CRYPTO variable])
		fi
	fi
		
	AC_MSG_RESULT([$OPENSSL_CRYPTO])

	#
	# Determining base OpenSSL directory
	#
	ssllibdir=$(dirname "$OPENSSL_CRYPTO")
	if test "$ssllibdir" = "/lib"; then
		# If library is in /lib assume includes are in /usr/include (that's typically the case)
		ssldir="/usr"
	else
		ssldir=$(dirname "$ssllibdir")
	fi

	#
	# Determining location of OpenSSL libraries
	#
	: ${OPENSSL_LDFLAGS:="-L$ssllibdir"}

	#
	# Determining location of OpenSSL includes and checking it
	#
	: ${OPENSSL_INCLUDES:="-I$ssldir/include"}

	save_CPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$OPENSSL_INCLUDES"

	AC_CHECK_HEADER([openssl/ssl.h], [],
		[AC_MSG_ERROR([Unable to determine OpenSSL includes location, that should be used with $OPENSSL_CRYPTO,
			please specify OPENSSL_INCLUDES, for example OPENSSL_INCLUDES="-I/usr/local/include"])], [])

	CPPFLAGS="$save_CPPFLAGS"

	#
	# Determining how to link libcrypto
	#
	if test -z "$OPENSSL_LIBS"; then
		openssl_libs_found=no

		save_CPPFLAGS="$CPPFLAGS"
		save_LDFLAGS="$LDFLAGS"
		save_LIBS="$LIBS"

		CPPFLAGS="$OPENSSL_INCLUDES $CPPFLAGS"
		LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"

		#
		# -l:filename method which is supported by recent versions of GNU ld
		#
		AC_MSG_CHECKING([whether the linker supports '-l:filename' option])
		openssl_libs="-l:$(basename $OPENSSL_CRYPTO)"
		LIBS="$openssl_libs"
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([#include <openssl/ssl.h>], [EVP_PKEY_new()])],
			[
				AC_MSG_RESULT([yes])
				openssl_libs_found=yes
			], [
				AC_MSG_RESULT([no])
			])

		#
		# -lnamespec.version method which is supported by ld on Darwin
		#
		if test $openssl_libs_found = no; then
			#
			# Shared library extension
			#
			module=no
			eval libcrypto_ext=$shrext_cmds

			AC_MSG_CHECKING([libcrypto version])
			libcrypto_ver=$(expr //${OPENSSL_CRYPTO} : '.*/libcrypto\(.*\)'${libcrypto_ext})
			if test -z "$libcrypto_ver"; then
				libcrypto_ver=$(expr //${OPENSSL_CRYPTO} : '.*/libcrypto'${libcrypto_ext}'\(.*\)')
			fi
			AC_MSG_RESULT([got "$libcrypto_ver"])
			
			AC_MSG_CHECKING([whether the linker supports '-lnamespec.version' option])
			openssl_libs="-lcrypto${libcrypto_ver}"
			LIBS="$openssl_libs"
			AC_LINK_IFELSE(
				[AC_LANG_PROGRAM([#include <openssl/ssl.h>], [EVP_PKEY_new()])],
				[
					AC_MSG_RESULT([yes])
					openssl_libs_found=yes
				], [
					AC_MSG_RESULT([no])
				])
		fi

		CPPFLAGS="$save_CPPFLAGS"
		LDFLAGS="$save_LDFLAGS"
		LIBS="$save_LIBS"

		if test $openssl_libs_found = no; then
			AC_MSG_WARN([Could not figure out how to link to specific libcrypto linking to default and
				hoping for the best. You can use OPENSSL_INCLUDES, OPENSSL_LIBS and OPENSSL_LDFLAGS
				to override the values manually.])
			openssl_libs="-lcrypto"
		fi

		OPENSSL_LIBS="$openssl_libs"
	fi

	AC_MSG_RESULT([Determined settings:])
	AC_MSG_RESULT([ OPENSSL_INCLUDES = $OPENSSL_INCLUDES])
	AC_MSG_RESULT([ OPENSSL_LDFLAGS  = $OPENSSL_LDFLAGS])
	AC_MSG_RESULT([ OPENSSL_LIBS     = $OPENSSL_LIBS])

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
			: ${CCN_INCLUDES:="-I$ccndir/include"}
			: ${CCN_LDFLAGS:="-L$ccndir/lib"}
			: ${CCN_LIBS:="-lccn"}
			: ${CCN_BIN:="$ccndir/bin"}
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

	AX_CCN_OPENSSL($CCN_BIN/ccnd, [], AC_MSG_ERROR([Unable to determine OpenSSL location]))
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
