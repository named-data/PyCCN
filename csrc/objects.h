/*
 * File:   objects.h
 * Author: takeda
 *
 * Created on July 20, 2011, 11:19 PM
 */

#ifndef OBJECTS_H
#  define	OBJECTS_H

struct completed_closure {
	PyObject *closure;
	struct completed_closure *next;
};

enum _pyccn_capsules {
	HANDLE = 1,
	CONTENT_OBJECT,
	PKEY,
	NAME,
	CLOSURE,
	SIGNED_INFO,
	KEY_LOCATOR
};

PyObject *CCNObject_New(enum _pyccn_capsules type, void *pointer);
int CCNObject_IsValid(enum _pyccn_capsules type, PyObject *capsule);
void *CCNObject_Get(enum _pyccn_capsules type, PyObject *capsule);

PyObject *CCNObject_New_Name(struct ccn_charbuf **name);
PyObject *CCNObject_New_Closure(struct ccn_closure **closure);
void CCNObject_Complete_Closure(PyObject *py_closure);
void CCNObject_Purge_Closures();

#endif	/* OBJECTS_H */

