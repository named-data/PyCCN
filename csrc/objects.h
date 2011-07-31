/*
 * File:   objects.h
 * Author: takeda
 *
 * Created on July 20, 2011, 11:19 PM
 */

#ifndef OBJECTS_H
#  define	OBJECTS_H

enum _pyccn_capsules {
	HANDLE = 1,
	CONTENT_OBJECT,
	PKEY,
	NAME,
	CLOSURE
};

PyObject *CCNObject_New(enum _pyccn_capsules type, void *pointer);
int CCNObject_IsValid(enum _pyccn_capsules type, PyObject *capsule);
void *CCNObject_Get(enum _pyccn_capsules type, PyObject *capsule);

PyObject *CCNObject_New_Name(struct ccn_charbuf **name);
PyObject *CCNObject_New_Closure(struct ccn_closure **closure);

#endif	/* OBJECTS_H */

