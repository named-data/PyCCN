#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([PyCCN], [0.2], [takeda@takeda.tk])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux])
AC_CONFIG_SRCDIR([csrc/pyccn.c])

AM_INIT_AUTOMAKE([foreign 1.11 silent-rules parallel-tests color-tests -Wall -Werror])
AM_SILENT_RULES([yes])
LT_INIT

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AX_CHECK_CCN(,AC_MSG_ERROR([CCNx is required to compile PyCCN]))

# Checks for header files.
AX_PYTHON_DEVEL([>= 2.7])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	csrc/Makefile
	python/Makefile
	tests/Makefile
	])
AC_CONFIG_FILES([tests/run], [chmod +x tests/run])
AC_OUTPUT
