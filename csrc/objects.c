/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#include "python_hdr.h"
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/signing.h>

#include <stdlib.h>

#include "pyccn.h"
#include "objects.h"
#include "util.h"

/*
static struct completed_closure *g_completed_closures;
 */

static struct type_to_name {
	enum _pyccn_capsules type;
	const char *name;
} g_types_to_names[] = {
	{CLOSURE, "Closure_ccn_data"},
	{CONTENT_OBJECT, "ContentObject_ccn_data"},
	{EXCLUSION_FILTER, "ExclusionFilter_ccn_data"},
	{HANDLE, "CCN_ccn_data"},
	{INTEREST, "Interest_ccn_data"},
	{KEY_LOCATOR, "KeyLocator_ccn_data"},
	{NAME, "Name_ccn_data"},
	{PKEY_PRIV, "PKEY_PRIV_ccn_data"},
	{PKEY_PUB, "PKEY_PUB_ccn_data"},
	{SIGNATURE, "Signature_ccn_data"},
	{SIGNED_INFO, "SignedInfo_ccn_data"},
	{SIGNING_PARAMS, "SigningParams_ccn_data"},
#ifdef NAMECRYPTO
	{NAMECRYPTO_STATE, "Namecrypto_state"},
#endif
	{0, NULL}
};

static inline const char *
type2name(enum _pyccn_capsules type)
{
	struct type_to_name *p;

	assert(type > 0);
	assert(type < sizeof(g_types_to_names) / sizeof(struct type_to_name));


	p = &g_types_to_names[type - g_types_to_names[0].type];
	assert(p->type == type);
	return p->name;
}

static inline enum _pyccn_capsules
name2type(const char *name)
{
	struct type_to_name *p;

	assert(name);

	for (p = g_types_to_names; p->type; p++)
		if (!strcmp(p->name, name))
			return p->type;

	debug("name = %s", name);
	panic("Got unknown type name");

	return 0; /* this shouldn't be reached */
}

static void
pyccn_Capsule_Destructor(PyObject *capsule)
{
	const char *name;
	void *pointer;
	enum _pyccn_capsules type;

	assert(PyCapsule_CheckExact(capsule));

	name = PyCapsule_GetName(capsule);
	type = name2type(name);

	pointer = PyCapsule_GetPointer(capsule, name);
	assert(pointer);

	switch (type) {
	case CLOSURE:
	{
		PyObject *py_obj_closure;
		struct ccn_closure *p = pointer;

		py_obj_closure = PyCapsule_GetContext(capsule);
		assert(py_obj_closure);
		Py_DECREF(py_obj_closure); /* No longer referencing Closure object */

		/* If we store something else, than ourselves, it probably is a bug */
		assert(capsule == p->data);

		free(p);
	}
		break;
	case CONTENT_OBJECT:
	{
		struct content_object_data *context;
		struct ccn_charbuf *p = pointer;

		context = PyCapsule_GetContext(capsule);
		if (context) {
			if (context->pco)
				free(context->pco);
			ccn_indexbuf_destroy(&context->comps);
			free(context);
		}
		ccn_charbuf_destroy(&p);
	}
		break;
	case HANDLE:
	{
		struct ccn *p = pointer;
		ccn_disconnect(p);
		ccn_destroy(&p);
	}
		break;
	case INTEREST:
	{
		struct interest_data *context;
		struct ccn_charbuf *p = pointer;

		context = PyCapsule_GetContext(capsule);
		if (context) {
			if (context->pi)
				free(context->pi);
			free(context);
		}
		ccn_charbuf_destroy(&p);
	}
		break;
	case PKEY_PRIV:
	case PKEY_PUB:
	{
		struct ccn_pkey *p = pointer;
		ccn_pubkey_free(p);
	}
		break;
	case EXCLUSION_FILTER:
	case KEY_LOCATOR:
	case NAME:
	case SIGNATURE:
	case SIGNED_INFO:
	{
		struct ccn_charbuf *p = pointer;
		ccn_charbuf_destroy(&p);
	}
		break;
	case SIGNING_PARAMS:
	{
		struct ccn_signing_params *p = pointer;

		if (p->template_ccnb)
			ccn_charbuf_destroy(&p->template_ccnb);

		free(p);
	}
		break;
#ifdef NAMECRYPTO
	case NAMECRYPTO_STATE:
		free(pointer);
		break;
#endif
	default:
		debug("Got capsule: %s\n", PyCapsule_GetName(capsule));
		panic("Unable to destroy the object: got an unknown capsule");
	}
}

PyObject *
CCNObject_New(enum _pyccn_capsules type, void *pointer)
{
	PyObject *capsule;
	int r;

	assert(pointer);
	capsule = PyCapsule_New(pointer, type2name(type), pyccn_Capsule_Destructor);
	if (!capsule)
		return NULL;

	switch (type) {
	case CONTENT_OBJECT:
	{
		struct content_object_data *context;

		context = calloc(1, sizeof(*context));
		JUMP_IF_NULL_MEM(context, error);

		r = PyCapsule_SetContext(capsule, context);
		if (r < 0) {
			free(context);
			goto error;
		}
		break;
	}
	case INTEREST:
	{
		struct interest_data *context;

		context = calloc(1, sizeof(*context));
		JUMP_IF_NULL_MEM(context, error);

		r = PyCapsule_SetContext(capsule, context);
		if (r < 0) {
			free(context);
			goto error;
		}
		break;
	}
	default:
		break;
	}

	return capsule;

error:
	Py_XDECREF(capsule);
	return NULL;
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
CCNObject_New_charbuf(enum _pyccn_capsules type,
		struct ccn_charbuf **charbuf)
{
	struct ccn_charbuf *p;
	PyObject *py_o;

	assert(type == CONTENT_OBJECT ||
			type == EXCLUSION_FILTER ||
			type == INTEREST ||
			type == KEY_LOCATOR ||
			type == NAME ||
			type == SIGNATURE ||
			type == SIGNED_INFO);

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
