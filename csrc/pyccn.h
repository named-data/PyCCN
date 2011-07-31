/*
 * pyccn.h
 *
 *  Created on: May 29, 2011
 *      Author: jburke
 *              Derek Kulinski
 */

#ifndef _PYCCN_H_
#  define _PYCCN_H_

#  if 1
#    define debug(...) fprintf(stderr, __VA_ARGS__)
#  else
#    define debug(...)
#  endif

#  define JUMP_IF_NULL(variable, label) \
do { \
	if (!variable) \
		goto label; \
} while(0)

#  define JUMP_IF_NEG(variable, label) \
do { \
	if (variable < 0) \
		goto label; \
} while(0)


extern PyObject *g_type_Name;
extern PyObject *g_type_Interest;
extern PyObject *g_type_ContentObject;
extern PyObject *g_type_Closure;
extern PyObject *g_type_Key;

extern PyObject *g_type_ExclusionFilter;
extern PyObject *g_type_KeyLocator;
extern PyObject *g_type_Signature;
extern PyObject *g_type_SignedInfo;
extern PyObject *g_type_SigningParams;
extern PyObject *g_type_UpcallInfo;

extern PyObject *g_PyExc_CCNError;
extern PyObject *g_PyExc_CCNNameError;

#endif /* _PYCCN_H_ */
