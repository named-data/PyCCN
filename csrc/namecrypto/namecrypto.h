/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 */

#ifndef _NAMECRYPTO_H_
#  define _NAMECRYPTO_H_

extern PyObject *_namecrypto_module;

#  if DEBUG_MSG
#    define debug(...) fprintf(stderr, __VA_ARGS__)
#  else
#    define debug(...)
#  endif

#  define JUMP_IF_ERR(label) \
do { \
	if (PyErr_Occurred()) \
		goto label; \
} while(0)

#  define JUMP_IF_NULL(variable, label) \
do { \
	if (!variable) \
		goto label; \
} while(0)

#  define JUMP_IF_NULL_MEM(variable, label) \
do { \
	if (!variable) { \
		PyErr_NoMemory(); \
		goto label; \
	} \
} while(0)

#  define JUMP_IF_NEG(variable, label) \
do { \
	if (variable < 0) \
		goto label; \
} while(0)

#  define JUMP_IF_NEG_MEM(variable, label) \
do { \
	if (variable < 0) { \
		PyErr_NoMemory(); \
		goto label; \
	} \
} while (0)

#  ifdef UNUSED
#  elif defined(__GNUC__)
#    define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#  elif defined(__LCLINT__)
#    define UNUSED(x) /*@unused@*/ x
#  else
#    define UNUSED(x) x
#  endif

#endif /* _NAMECRYPTO_H_ */
