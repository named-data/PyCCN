/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#define PY_SSIZE_T_CLEAN 1
#include "python_hdr.h"
#include <ccn/ccn.h>

#include "pyccn.h"
#include "util.h"
#include "key_utils.h"
#include "methods.h"
#include "methods_contentobject.h"
#include "methods_interest.h"
#include "methods_key.h"
#include "methods_signedinfo.h"
#include "objects.h"


// Registering callbacks

PyObject *
_pyccn_cmd_generate_RSA_key(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_key, *py_o;
	long keylen;
	PyObject *py_private_key = NULL, *py_public_key = NULL,
			*py_public_key_digest = NULL;
	int public_key_digest_len, r;

	if (!PyArg_ParseTuple(args, "Ol", &py_key, &keylen))
		return NULL;

	if (strcmp(py_key->ob_type->tp_name, "Key")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Key");
		return NULL;
	}

	r = generate_key(keylen, &py_private_key, &py_public_key,
			&py_public_key_digest, &public_key_digest_len);
	if (r < 0) {
		PyErr_SetString(g_PyExc_CCNKeyError, "Unable to genearate a key");
		return NULL;
	}

	r = PyObject_SetAttrString(py_key, "ccn_data_private", py_private_key);
	Py_CLEAR(py_private_key);
	JUMP_IF_NEG(r, error);

	r = PyObject_SetAttrString(py_key, "ccn_data_public", py_public_key);
	Py_CLEAR(py_public_key);
	JUMP_IF_NEG(r, error);

	py_o = PyUnicode_FromString("RSA");
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_key, "type", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	r = PyObject_SetAttrString(py_key, "publicKeyID", py_public_key_digest);
	Py_DECREF(py_public_key_digest);
	JUMP_IF_NEG(r, error);

	Py_RETURN_NONE;

error:
	Py_XDECREF(py_public_key_digest);
	Py_XDECREF(py_public_key);
	Py_XDECREF(py_private_key);
	return NULL;
}


// ** Methods of SignedInfo
//
// Signing
/* We don't expose this because ccn_signing_params is not that useful to us
 * see comments above on this.
static PyObject* // int
_pyccn_ccn_chk_signing_params(PyObject* self, PyObject* args) {
	// Build internal signing params struct
	return 0;
}
 */

/* We don't expose this because it is done automatically in the Python SignedInfo object

static PyObject*
_pyccn_ccn_signed_info_create(PyObject* self, PyObject* args) {
	return 0;
}

 */

// ************
// SigningParams
//
//

// Note that SigningParams information is essentially redundant
// to what's in SignedInfo, and is internal to the
// ccn libraries.
// See the source for ccn_sign_content, for example.
//
// To use it requires working with keystores & hashtables to
// reference keys, which requires accessing private functions in the library
//
// So, we don't provide "to_ccn" functionality here, only "from_ccn" in case
// there is a need to parse a struct coming from the c library.


// Can be called directly from c library
//
// Pointer to a struct ccn_signing_params
//

static PyObject *
obj_SigningParams_from_ccn(PyObject *py_signing_params)
{
	struct ccn_signing_params *signing_params;
	PyObject *py_obj_SigningParams, *py_o;
	int r;

	assert(g_type_SigningParams);

	debug("SigningParams_from_ccn start\n");

	signing_params = CCNObject_Get(SIGNING_PARAMS, py_signing_params);

	// 1) Create python object
	py_obj_SigningParams = PyObject_CallObject(g_type_SigningParams, NULL);
	JUMP_IF_NULL(py_obj_SigningParams, error);

	// 2) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	r = PyObject_SetAttrString(py_obj_SigningParams, "ccn_data",
			py_signing_params);
	JUMP_IF_NEG(r, error);


	// 3) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString

	py_o = _pyccn_Int_FromLong(signing_params->sp_flags);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_SigningParams, "flags", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	py_o = _pyccn_Int_FromLong(signing_params->type);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_SigningParams, "type", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	py_o = _pyccn_Int_FromLong(signing_params->freshness);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_SigningParams, "freshness", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	py_o = _pyccn_Int_FromLong(signing_params->api_version);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_SigningParams, "apiVersion", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	if (signing_params->template_ccnb &&
			signing_params->template_ccnb->length > 0) {
		PyObject *py_signed_object;
		struct ccn_charbuf *signed_object;

		py_signed_object = CCNObject_New_charbuf(SIGNED_INFO, &signed_object);
		JUMP_IF_NULL(py_signed_object, error);

		r = ccn_charbuf_append_charbuf(signed_object,
				signing_params->template_ccnb);
		if (r < 0) {
			Py_DECREF(py_signed_object);
			PyErr_NoMemory();
			goto error;
		}

		py_o = SignedInfo_obj_from_ccn(py_signed_object);
		Py_DECREF(py_signed_object);
		JUMP_IF_NULL(py_o, error);
	} else
		py_o = (Py_INCREF(Py_None), Py_None);

	r = PyObject_SetAttrString(py_obj_SigningParams, "template", py_o);
	Py_DECREF(py_o);

	// Right now we're going to set this to the byte array corresponding
	// to the key hash, but this is not ideal
	// TODO:  Figure out how to deal with keys here...
	py_o = PyByteArray_FromStringAndSize((char *) signing_params->pubid,
			sizeof(signing_params->pubid));
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_SigningParams, "key", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	// 4) Return the created object
	debug("SigningParams_from_ccn ends\n");

	return py_obj_SigningParams;

error:
	Py_XDECREF(py_obj_SigningParams);
	return NULL;
}

PyObject *
_pyccn_SigningParams_from_ccn(PyObject *UNUSED(self),
		PyObject *py_signing_params)
{
	if (!CCNObject_IsValid(SIGNING_PARAMS, py_signing_params)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN SigningParams");
		return NULL;
	}

	return obj_SigningParams_from_ccn(py_signing_params);
}

PyObject *
_pyccn_cmd_dump_charbuf(PyObject *UNUSED(self), PyObject *py_charbuf)
{
	const struct ccn_charbuf *charbuf;
	static const enum _pyccn_capsules types[] = {
		CONTENT_OBJECT,
		EXCLUSION_FILTER,
		INTEREST,
		KEY_LOCATOR,
		NAME,
		SIGNATURE,
		SIGNED_INFO
	};
	enum _pyccn_capsules type;
	static const size_t len = sizeof(types) / sizeof(type);

	for (size_t i = 0; i < len; i++) {
		if (CCNObject_IsValid(types[i], py_charbuf)) {
			type = types[i];
			goto success;
		}
	}

	PyErr_SetString(PyExc_TypeError, "Expected charbuf type");
	return NULL;

success:
	charbuf = CCNObject_Get(type, py_charbuf);

	return PyBytes_FromStringAndSize((char *) charbuf->buf, charbuf->length);
}

PyObject *
_pyccn_cmd_new_charbuf(PyObject *UNUSED(self), PyObject *args)
{
	const char *type, *charbuf_data;
	Py_ssize_t charbuf_data_len;
	struct ccn_charbuf *charbuf;
	PyObject *result = NULL;
	int r;
	enum _pyccn_capsules capsule_type;

	if (!PyArg_ParseTuple(args, "ss#", &type, &charbuf_data, &charbuf_data_len))
		return NULL;

	if (strcmp(type, "KeyLocator_ccn_data")) {
		PyErr_SetString(PyExc_ValueError, "Expected valid type "
				"('KeyLocator_ccn_data')");
		goto error;
	}
	capsule_type = KEY_LOCATOR;

	result = CCNObject_New_charbuf(capsule_type, &charbuf);
	JUMP_IF_NULL(result, error);

	r = ccn_charbuf_append(charbuf, charbuf_data, charbuf_data_len);
	JUMP_IF_NEG_MEM(r, error);

	return result;

error:
	Py_XDECREF(result);
	return NULL;
}
