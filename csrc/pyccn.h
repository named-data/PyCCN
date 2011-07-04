/*
 * pyccn.h
 *
 *  Created on: May 29, 2011
 *      Author: jburke
 */

#ifndef _PYCCN_H_
#  define _PYCCN_H_

extern PyObject* g_type_Name;
extern PyObject* g_type_Interest;
extern PyObject* g_type_ContentObject;
extern PyObject* g_type_Key;

extern PyObject* g_type_ExclusionFilter;
extern PyObject* g_type_KeyLocator;
extern PyObject* g_type_Signature;
extern PyObject* g_type_SignedInfo;
extern PyObject* g_type_SigningParams;
extern PyObject* g_type_UpcallInfo;

extern PyObject* g_module_ContentObject;

void __ccn_destroy(void* p);
void __ccn_closure_destroy(void *p);

enum ccn_upcall_res __ccn_upcall_handler(struct ccn_closure *selfp,
		enum ccn_upcall_kind upcall_kind,
		struct ccn_upcall_info *info);

#endif /* _PYCCN_H_ */
