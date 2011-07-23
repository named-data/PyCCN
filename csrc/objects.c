#include <Python.h>
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/signing.h>

#include <stdlib.h>

#include "misc.h"
#include "objects.h"

static inline const char *
type2name(enum _pyccn_capsules type)
{
	switch (type) {
	case HANDLE:
		return "CCN_ccn_data";
	case CONTENT_OBJECT:
		return "ContentObject_ccn_data";
	case PKEY:
		return "PKEY_ccn_data";
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
	} else if (CCNObject_IsValid(HANDLE, capsule)) {
		struct ccn *p = pointer;
		ccn_disconnect(p); // XXX: Ok to call this even if already disconn?
		ccn_destroy(&p);
	} else if (CCNObject_IsValid(PKEY, capsule)) {
		struct ccn_pkey *p = pointer;
		ccn_pubkey_free(p); // what about private keys?
	} else
		panic("Unable to destroy unknown capsule");
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
	return PyCapsule_GetPointer(capsule, type2name(type));
}
