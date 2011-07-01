#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([PyCCN], [0.1], [takeda@takeda.tk])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([csrc/pyccn.c])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])
LT_INIT

# Checks for programs.
AC_PROG_CC
#AC_PROG_LIBTOOL

# Checks for libraries.
AX_CHECK_CCN(,AC_MSG_ERROR([CCNx is required]))

# Checks for header files.
AX_PYTHON_DEVEL

# Checks for typedefs, structures, and compiler characteristics.
#AC_TYPE_SIZE_T
#AC_TYPE_SSIZE_T

# Checks for library functions.

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile
                 csrc/Makefile])
AC_OUTPUT
