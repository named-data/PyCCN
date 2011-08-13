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
	case CLOSURE:
		return "Closure_ccn_data";
	case CONTENT_OBJECT:
		return "ContentObject_ccn_data";
	case CONTENT_OBJECT_COMPONENTS:
		return "ContentObjects_ccn_data_components";
	case HANDLE:
		return "CCN_ccn_data";
	case KEY_LOCATOR:
		return "KeyLocator_ccn_data";
	case NAME:
		return "Name_ccn_data";
	case PARSED_CONTENT_OBJECT:
		return "ParsedContentObject_ccn_data";
	case PKEY:
		return "PKEY_ccn_data";
	case SIGNATURE:
		return "Signature_ccn_data";
	case SIGNED_INFO:
		return "SignedInfo_ccn_data";
	case UPCALL_INFO:
		return "UpcallInfo_ccn_data";
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

	if (CCNObject_IsValid(CLOSURE, capsule)) {
		PyObject *py_closure;
		struct ccn_closure *p = pointer;

		py_closure = PyCapsule_GetContext(capsule);
		assert(py_closure);
		Py_DECREF(py_closure); /* No longer referencing Closure object */

		/* If we store something else, than ourselves, it probably is a bug */
		assert(capsule == p->data);

		free(p);
	} else if (CCNObject_IsValid(CONTENT_OBJECT, capsule)) {
		struct ccn_charbuf *p = pointer;
		ccn_charbuf_destroy(&p);
	} else if (CCNObject_IsValid(CONTENT_OBJECT_COMPONENTS, capsule)) {
		struct ccn_indexbuf *p = pointer;
		ccn_indexbuf_destroy(&p);
	} else if (CCNObject_IsValid(HANDLE, capsule)) {
		struct ccn *p = pointer;
		ccn_disconnect(p);
		ccn_destroy(&p);
	} else if (CCNObject_IsValid(KEY_LOCATOR, capsule)) {
		struct ccn_charbuf *p = pointer;
		ccn_charbuf_destroy(&p);
	} else if (CCNObject_IsValid(NAME, capsule)) {
		struct ccn_charbuf *p = pointer;
		ccn_charbuf_destroy(&p);
	} else if (CCNObject_IsValid(PARSED_CONTENT_OBJECT, capsule)) {
		free(pointer);
	} else if (CCNObject_IsValid(PKEY, capsule)) {
		struct ccn_pkey *p = pointer;
		ccn_pubkey_free(p); // what about private keys?
	} else if (CCNObject_IsValid(SIGNATURE, capsule)) {
		struct ccn_charbuf *p = pointer;
		ccn_charbuf_destroy(&p);
	} else if (CCNObject_IsValid(SIGNED_INFO, capsule)) {
		struct ccn_charbuf *p = pointer;
		ccn_charbuf_destroy(&p);
	} else {
		debug("Got capsule: %s\n", PyCapsule_GetName(capsule));
		panic("Unable to destroy the object: got an unknown capsule");
	}
}

PyObject *
CCNObject_New(enum _pyccn_capsules type, void *pointer)
{
	PyObject *r;

	assert(pointer);
	r = PyCapsule_New(pointer, type2name(type), pyccn_Capsule_Destructor);

	return r;
}

PyObject *
CCNObject_Borrow(enum _pyccn_capsules type, void *pointer)
{
	PyObject *r;

	assert(pointer);
	r = PyCapsule_New(pointer, type2name(type), NULL);
	assert(r);

	return r;
}

int
CCNObject_ReqType(enum _pyccn_capsules type, PyObject *capsule)
{
	int r;
	const char *t = type2name(type);

	r = PyCapsule_IsValid(capsule, t);
	if (!r)
		PyErr_Format(PyExc_TypeError, "Argument needs to be of %s type", t);

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
	if (!p)
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

PyObject *
CCNObject_New_ContentObject(struct ccn_charbuf **content_object)
{
	struct ccn_charbuf *p;
	PyObject *py_co;

	p = ccn_charbuf_create();
	if (!p)
		return PyErr_NoMemory();

	py_co = CCNObject_New(CONTENT_OBJECT, p);
	if (!py_co) {
		ccn_charbuf_destroy(&p);
		return NULL;
	}

	if (content_object)
		*content_object = p;

	return py_co;
}

PyObject *
CCNObject_New_ParsedContentObject(struct ccn_parsed_ContentObject **pco)
{
	struct ccn_parsed_ContentObject *p;
	PyObject *py_o;

	p = malloc(sizeof(*p));
	if (!p)
		return PyErr_NoMemory();

	py_o = CCNObject_New(PARSED_CONTENT_OBJECT, p);
	if (!py_o) {
		free(p);
		return NULL;
	}

	if (pco)
		*pco = p;

	return py_o;
}

PyObject *
CCNObject_New_ContentObjectComponents(struct ccn_indexbuf **comps)
{
	struct ccn_indexbuf *p;
	PyObject *py_o;

	p = ccn_indexbuf_create();
	if (!p)
		return PyErr_NoMemory();

	py_o = CCNObject_New(CONTENT_OBJECT_COMPONENTS, p);
	if (!py_o) {
		ccn_indexbuf_destroy(&p);
		return NULL;
	}

	if (comps)
		*comps = p;

	return py_o;
}

PyObject *
CCNObject_New_charbuf(enum _pyccn_capsules type,
		struct ccn_charbuf **charbuf)
{
	struct ccn_charbuf *p;
	PyObject *py_o;

	p = ccn_charbuf_create();
	if (!p)
		return PyErr_NoMemory();

	py_o = CCNObject_New(type, p);
	if (!py_o) {
		ccn_charbuf_destroy(&p);
		return NULL;
	}

	if (charbuf)
		*charbuf = p;

	return py_o;
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