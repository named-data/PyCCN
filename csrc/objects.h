/*
 * File:   objects.h
 * Author: takeda
 *
 * Created on July 20, 2011, 11:19 PM
 */

#ifndef OBJECTS_H
#  define	OBJECTS_H

#  if 0

struct completed_closure {
	PyObject *closure;
	struct completed_closure *next;
};
#  endif

enum _pyccn_capsules {
	CLOSURE = 1,
	CONTENT_OBJECT,
	CONTENT_OBJECT_COMPONENTS,
	HANDLE,
	KEY_LOCATOR,
	NAME,
	PARSED_CONTENT_OBJECT,
	PKEY,
	SIGNATURE,
	SIGNED_INFO,
	UPCALL_INFO
};

PyObject *CCNObject_New(enum _pyccn_capsules type, void *pointer);
PyObject *CCNObject_Borrow(enum _pyccn_capsules type, void *pointer);
int CCNObject_ReqType(enum _pyccn_capsules type, PyObject *capsule);
int CCNObject_IsValid(enum _pyccn_capsules type, PyObject *capsule);
void *CCNObject_Get(enum _pyccn_capsules type, PyObject *capsule);

PyObject *CCNObject_New_Name(struct ccn_charbuf **name);
PyObject *CCNObject_New_Closure(struct ccn_closure **closure);
PyObject *CCNObject_New_ContentObject(struct ccn_charbuf **content_object);
PyObject *CCNObject_New_ParsedContentObject(
		struct ccn_parsed_ContentObject **pco);
PyObject *CCNObject_New_ContentObjectComponents(
		struct ccn_indexbuf **comps);
void CCNObject_Complete_Closure(PyObject *py_closure);
void CCNObject_Purge_Closures();

#endif	/* OBJECTS_H */
