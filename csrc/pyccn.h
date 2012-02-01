/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#ifndef _PYCCN_H_
#  define _PYCCN_H_

enum e_class_type {
	CCN,
	Closure,
	ContentObject,
	ExclusionFilter,
	Interest,
	Key,
	KeyLocator,
	Name,
	Signature,
	SignedInfo,
	SigningParams,
	UpcallInfo,
	CLASS_TYPE_COUNT
};

#define MAX_RUN_STATES 5

struct pyccn_run_state {
	struct ccn *handle;
	PyThreadState *thread_state;
	struct pyccn_run_state *next;
};

struct pyccn_state {
	struct pyccn_run_state *run_state;
	PyObject *class_type[CLASS_TYPE_COUNT];
};

extern PyObject *_pyccn_module;

#  if PY_MAJOR_VERSION >= 3
#    define GETSTATE(m) ((struct pyccn_state *)PyModule_GetState(m))
#  else
extern struct pyccn_state _pyccn_state;
#    define GETSTATE(m) (&_pyccn_state)
#  endif

PyObject *_pyccn_get_type(enum e_class_type type);

#  define g_type_CCN              _pyccn_get_type(CCN)
#  define g_type_Closure          _pyccn_get_type(Closure)
#  define g_type_ContentObject    _pyccn_get_type(ContentObject)
#  define g_type_ExclusionFilter  _pyccn_get_type(ExclusionFilter)
#  define g_type_Interest         _pyccn_get_type(Interest)
#  define g_type_Key              _pyccn_get_type(Key)
#  define g_type_KeyLocator       _pyccn_get_type(KeyLocator)
#  define g_type_Name             _pyccn_get_type(Name)
#  define g_type_Signature        _pyccn_get_type(Signature)
#  define g_type_SignedInfo       _pyccn_get_type(SignedInfo)
#  define g_type_SigningParams    _pyccn_get_type(SigningParams)
#  define g_type_UpcallInfo       _pyccn_get_type(UpcallInfo)

extern PyObject *g_PyExc_CCNError;
extern PyObject *g_PyExc_CCNNameError;
extern PyObject *g_PyExc_CCNKeyLocatorError;
extern PyObject *g_PyExc_CCNSignatureError;
extern PyObject *g_PyExc_CCNSignedInfoError;
extern PyObject *g_PyExc_CCNInterestError;
extern PyObject *g_PyExc_CCNExclusionFilterError;
extern PyObject *g_PyExc_CCNKeyError;
extern PyObject *g_PyExc_CCNContentObjectError;

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

#endif /* _PYCCN_H_ */
