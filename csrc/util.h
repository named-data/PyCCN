/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#ifndef _UTIL_H_
#  define	_UTIL_H_

#  if PY_MAJOR_VERSION >= 3
#    define _pyccn_STRING_CHECK(op) PyUnicode_Check(op)
#    define _pyccn_Int_Check(val) PyLong_Check(val)
#    define _pyccn_Int_FromLong(val) PyLong_FromLong(val)
#    define _pyccn_Int_AsLong(val) PyLong_AsLong(val)
#  else
#    define _pyccn_STRING_CHECK(op) (PyString_Check(op) || PyUnicode_Check(op))
#    define _pyccn_Int_Check(val) PyInt_Check(val)
#    define _pyccn_Int_FromLong(val) PyInt_FromLong(val)
#    define _pyccn_Int_AsLong(val) PyInt_AsLong(val)
#  endif


void dump_charbuf(struct ccn_charbuf* c, FILE* fp);
void panic(const char *message);
void print_object(const PyObject *object);
PyObject *_pyccn_unicode_to_utf8(PyObject *string, char **buffer,
		Py_ssize_t *length);
FILE *_pyccn_open_file_handle(PyObject *py_file, const char *mode);
int _pyccn_close_file_handle(FILE *fh);
void *_pyccn_run_state_add(struct ccn *handle);
struct pyccn_run_state *_pyccn_run_state_find(struct ccn *handle);
void _pyccn_run_state_clear(void *handle);

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

#endif	/* _UTIL_H_ */
