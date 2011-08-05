#include <Python.h>
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/signing.h>

#include <stdlib.h>

#include "pyccn.h"
#include "misc.h"
#include "objects.h"

/*
static struct completed_closure *g_completed_closures;
*/

static inline const char *
type2name(enum _pyccn_capsules type)
{
	switch (type) {
	case NAME:
		return "Name_ccn_data";
	case HANDLE:
		return "CCN_ccn_data";
	case CONTENT_OBJECT:
		return "ContentObject_ccn_data";
	case SIGNED_INFO:
		return "SignedInfo_ccn_data";
	case CLOSURE:
		return "Closure_ccn_data";
	case PKEY:
		return "PKEY_ccn_data";
	case KEY_LOCATOR:
		return "KeyLocator_ccn_data";
	default:
		panic("Unknown type");
	}

	return NULL;
}

static void
pyccn_Capsule_Destructor(PyObject *capsule)
{
	const char *name;
	void *pointer;

	assert(PyCapsule_CheckExact(capsule));

	name = PyCapsule_GetName(capsule);
	pointer = PyCapsule_GetPointer(capsule, name);
	assert(pointer);

	if (CCNObject_IsValid(CONTENT_OBJECT, capsule)) {
		struct ccn_charbuf *p = pointer;
		ccn_charbuf_destroy(&p);
	} else if (CCNObject_IsValid(NAME, capsule)) {
		struct ccn_charbuf *p = pointer;
		ccn_charbuf_destroy(&p);
	} else if (CCNObject_IsValid(SIGNED_INFO, capsule)) {
		struct ccn_charbuf *p = pointer;
		ccn_charbuf_destroy(&p);
	} else if (CCNObject_IsValid(KEY_LOCATOR, capsule)) {
		struct ccn_charbuf *p = pointer;
		ccn_charbuf_destroy(&p);
	} else if (CCNObject_IsValid(CLOSURE, capsule)) {
		PyObject *py_closure;
		struct ccn_closure *p = pointer;

		py_closure = PyCapsule_GetContext(capsule);
		assert(py_closure);
		Py_DECREF(py_closure); /* No longer referencing Closure object */

		/* If we store something else, than ourselves, it probably is a bug */
		assert(capsule == p->data);

		free(p);
	} else if (CCNObject_IsValid(HANDLE, capsule)) {
		struct ccn *p = pointer;
		ccn_disconnect(p);
		ccn_destroy(&p);
	} else if (CCNObject_IsValid(PKEY, capsule)) {
		struct ccn_pkey *p = pointer;
		ccn_pubkey_free(p); // what about private keys?
	} else
		panic("Unable to destroy the object: got an unknown capsule");
}

PyObject *
CCNObject_New(enum _pyccn_capsules type, void *pointer)
{
	PyObject *r;

	assert(pointer);
	r = PyCapsule_New(pointer, type2name(type), pyccn_Capsule_Destructor);
	assert(r);

	return r;
}

int
CCNObject_IsValid(enum _pyccn_capsules type, PyObject *capsule)
{
	return PyCapsule_IsValid(capsule, type2name(type));
}

void *
CCNObject_Get(enum _pyccn_capsules type, PyObject *capsule)
{
	void *p;

	assert(CCNObject_IsValid(type, capsule));
	p = PyCapsule_GetPointer(capsule, type2name(type));
	assert(p);

	return p;
}

PyObject *
CCNObject_New_Name(struct ccn_charbuf **name)
{
	struct ccn_charbuf *p;
	PyObject *py_cname;

	p = ccn_charbuf_create();
	if (p < 0)
		return PyErr_NoMemory();

	py_cname = CCNObject_New(NAME, p);
	if (!py_cname) {
		ccn_charbuf_destroy(&p);
		return NULL;
	}

	if (name)
		*name = p;

	return py_cname;
}

PyObject *
CCNObject_New_Closure(struct ccn_closure **closure)
{
	struct ccn_closure *p;
	PyObject *result;

	p = calloc(1, sizeof(*p));
	if (!p)
		return PyErr_NoMemory();

	result = CCNObject_New(CLOSURE, p);
	if (!result) {
		free(p);
		return NULL;
	}

	if (closure)
		*closure = p;

	return result;
}

#if 0
void
CCNObject_Complete_Closure(PyObject *py_closure)
{
	struct completed_closure *p;

	debug("Adding called closure to be purged\n");

	assert(py_closure);
	p = malloc(sizeof(*p));
	p->closure = py_closure;
	p->next = g_completed_closures;
	g_completed_closures = p;
}

void
CCNObject_Purge_Closures()
{
	struct completed_closure *p;

	debug("Purging old closures\n");

	while (g_completed_closures) {
		p = g_completed_closures;
		Py_DECREF(p->closure);
		g_completed_closures = p->next;
		free(p);
	}
}
#endif