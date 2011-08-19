/*
 * Copyright (c) 2011, Regents of the University of California
 * All rights reserved.
 * Written by: Jeff Burke <jburke@ucla.edu>
 *             Derek Kulinski <takeda@takeda.tk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Regents of the University of California nor
 *       the names of its contributors may be used to endorse or promote
 *       products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL REGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <Python.h>
#include <ccn/ccn.h>

#include "pyccn.h"
#include "methods_key.h"
#include "methods_name.h"
#include "methods_signature.h"
#include "methods_signedinfo.h"
#include "objects.h"

static PyObject *
Content_from_ccn_parsed(struct ccn_charbuf *content_object,
		struct ccn_parsed_ContentObject *parsed_content_object)
{
	const char *value;
	size_t size;
	PyObject *py_content;
	int r;

	r = ccn_content_get_value(content_object->buf, content_object->length,
			parsed_content_object, (const unsigned char **) &value, &size);
	if (r < 0) {
		PyErr_Format(g_PyExc_CCNError, "ccn_content_get_value() returned"
				" %d", r);
		return NULL;
	}

	py_content = PyByteArray_FromStringAndSize(value, size);
	if (!py_content)
		return NULL;

	return py_content;
}

// ** Methods of ContentObject
//
// Content Objects

PyObject *
ContentObject_from_ccn_parsed(PyObject *py_content_object,
		PyObject *py_parsed_content_object, PyObject *py_components)
{
	struct ccn_charbuf *content_object;
	struct ccn_parsed_ContentObject *parsed_content_object;
	PyObject *py_ContentObject, *py_o;
	int r;
	struct ccn_charbuf *signature;
	PyObject *py_signature;
	struct ccn_charbuf *signed_info;
	PyObject *py_signed_info;

	if (!CCNObject_ReqType(CONTENT_OBJECT, py_content_object))
		return NULL;

	if (!CCNObject_ReqType(PARSED_CONTENT_OBJECT, py_parsed_content_object))
		return NULL;

	if (!CCNObject_ReqType(CONTENT_OBJECT_COMPONENTS, py_components))
		return NULL;

	content_object = CCNObject_Get(CONTENT_OBJECT, py_content_object);
	parsed_content_object = CCNObject_Get(PARSED_CONTENT_OBJECT,
			py_parsed_content_object);

	debug("ContentObject_from_ccn_parsed content_object->length=%zd\n",
			content_object->length);

	py_ContentObject = PyObject_CallObject(g_type_ContentObject, NULL);
	if (!py_ContentObject)
		return NULL;

	/* Name */
	py_o = Name_from_ccn_parsed(py_content_object, py_parsed_content_object);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_ContentObject, "name", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	/* Content */
	py_o = Content_from_ccn_parsed(content_object, parsed_content_object);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_ContentObject, "content", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	/* Signature */
	debug("ContentObject_from_ccn_parsed Signature\n");
	py_signature = CCNObject_New_charbuf(SIGNATURE, &signature);
	JUMP_IF_NULL(py_signature, error);
	r = ccn_charbuf_append(signature,
			&content_object->buf[parsed_content_object->offset[CCN_PCO_B_Signature]],
			(size_t) (parsed_content_object->offset[CCN_PCO_E_Signature]
			- parsed_content_object->offset[CCN_PCO_B_Signature]));
	if (r < 0) {
		PyErr_NoMemory();
		Py_DECREF(py_signature);
		goto error;
	}

	py_o = obj_Signature_obj_from_ccn(py_signature);
	Py_DECREF(py_signature);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_ContentObject, "signature", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	debug("ContentObject_from_ccn_parsed SignedInfo\n");

	py_signed_info = CCNObject_New_charbuf(SIGNED_INFO, &signed_info);
	JUMP_IF_NULL(py_signed_info, error);

	r = ccn_charbuf_append(signed_info,
			&content_object->buf[parsed_content_object->offset[CCN_PCO_B_SignedInfo]],
			(size_t) (parsed_content_object->offset[CCN_PCO_E_SignedInfo]
			- parsed_content_object->offset[CCN_PCO_B_SignedInfo]));
	if (r < 0) {
		PyErr_NoMemory();
		Py_DECREF(py_signed_info);
		goto error;
	}

	py_o = SignedInfo_obj_from_ccn(py_signed_info);
	Py_DECREF(py_signed_info);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_ContentObject, "signedInfo", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	debug("ContentObject_from_ccn_parsed DigestAlgorithm\n");
	// TODO...  Note this seems to default to nothing in the library...?
	r = PyObject_SetAttrString(py_ContentObject, "digestAlgorithm", Py_None);
	JUMP_IF_NEG(r, error);

	/* Original data  */
	debug("ContentObject_from_ccn_parsed ccn_data\n");
	r = PyObject_SetAttrString(py_ContentObject, "ccn_data", py_content_object);
	JUMP_IF_NEG(r, error);

	debug("ContentObject_from_ccn_parsed ccn_data_parsed\n");
	r = PyObject_SetAttrString(py_ContentObject, "ccn_data_parsed",
			py_parsed_content_object);
	JUMP_IF_NEG(r, error);

	debug("ContentObject_from_ccn_parsed ccn_data_components\n");
	r = PyObject_SetAttrString(py_ContentObject, "ccn_data_components",
			py_components);
	JUMP_IF_NEG(r, error);

	debug("ContentObject_from_ccn_parsed complete\n");

	return py_ContentObject;

error:
	Py_XDECREF(py_ContentObject);
	return NULL;
}

// Can be called directly from c library
#if 0

PyObject*
ContentObject_from_ccn(struct ccn_charbuf* content_object)
{
	struct ccn_parsed_ContentObject* parsed_content_object = calloc(sizeof(struct ccn_parsed_ContentObject), 1);
	struct ccn_indexbuf* components = ccn_indexbuf_create();
	ccn_parse_ContentObject(content_object->buf, content_object->length, parsed_content_object, components);
	// TODO: Check result
	PyObject* CO = ContentObject_from_ccn_parsed(content_object, parsed_content_object, components);
	free(parsed_content_object);
	ccn_indexbuf_destroy(&components);
	return CO;
}
#endif

PyObject *
_pyccn_content_to_bytearray(PyObject *UNUSED(self), PyObject *arg)
{
	PyObject *result;

	if (arg == Py_None)
		result = (Py_INCREF(Py_None), Py_None);
	else if (PyFloat_Check(arg) || PyLong_Check(arg) || PyInt_Check(arg)) {
		PyObject *s;

		s = PyObject_Str(arg);
		if (!s)
			return NULL;

		result = PyByteArray_FromObject(s);
		Py_DECREF(s);
	} else
		result = PyByteArray_FromObject(arg);

	return result;
}

PyObject *
_pyccn_ContentObject_to_ccn(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_content_object, *py_name, *py_content, *py_signed_info,
			*py_key;
	PyObject *py_o = NULL, *ret = NULL;
	struct ccn_charbuf *name, *signed_info, *content_object = NULL;
	struct ccn_pkey *private_key;
	const char *digest_alg = NULL;
	char *content;
	int content_len, r;

	if (!PyArg_ParseTuple(args, "OOOOO", &py_content_object, &py_name,
			&py_content, &py_signed_info, &py_key))
		return NULL;

	if (strcmp(py_content_object->ob_type->tp_name, "ContentObject")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a ContentObject as arg 1");
		return NULL;
	}

	if (!CCNObject_IsValid(NAME, py_name)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Name as arg 2");
		return NULL;
	} else
		name = CCNObject_Get(NAME, py_name);

	if (py_content != Py_None && !PyByteArray_Check(py_content)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a ByteArray as arg 3");
		return NULL;
	} else if (py_content == Py_None) {
		content = NULL;
		content_len = 0;
	} else {
		content = PyByteArray_AS_STRING(py_content);
		content_len = PyByteArray_GET_SIZE(py_content);
	}

	if (!CCNObject_IsValid(SIGNED_INFO, py_signed_info)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN SignedInfo as arg 4");
		return NULL;
	} else
		signed_info = CCNObject_Get(SIGNED_INFO, py_signed_info);

	if (strcmp(py_key->ob_type->tp_name, "Key")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Key as arg 4");
		return NULL;
	}

	// DigestAlgorithm
	py_o = PyObject_GetAttrString(py_content_object, "digestAlgorithm");
	if (py_o != Py_None) {
		PyErr_SetString(PyExc_NotImplementedError, "non-default digest"
				" algorithm not yet supported");
		goto error;
	}
	Py_CLEAR(py_o);

	// Key
	private_key = Key_to_ccn_private(py_key);

	// Note that we don't load this key into the keystore hashtable in the library
	// because it makes this method require access to a ccn handle, and in fact,
	// ccn_sign_content just uses what's in signedinfo (after an error check by
	// chk_signing_params and then calls ccn_encode_ContentObject anyway
	//
	// Encode the content object

	// Build the ContentObject here.
	content_object = ccn_charbuf_create();
	JUMP_IF_NULL_MEM(content_object, error);

	r = ccn_encode_ContentObject(content_object, name, signed_info, content,
			content_len, digest_alg, private_key);

	debug("ccn_encode_ContentObject res=%d\n", r);
	if (r < 0) {
		ccn_charbuf_destroy(&content_object);
		PyErr_SetString(g_PyExc_CCNError, "Unable to encode ContentObject");
		goto error;
	}

	ret = CCNObject_New(CONTENT_OBJECT, content_object);

error:
	Py_XDECREF(py_o);
	return ret;
}

#if 0

PyObject *
_pyccn_ContentObject_from_ccn(PyObject *self, PyObject *args)
{
	PyObject *py_co, *py_parsed_co = Py_None, *py_co_components = Py_None;

	if (!PyArg_ParseTuple(args, "O|OO", &py_co, &py_parsed_co,
			&py_co_components))
		return NULL;

	if (!CCNObject_IsValid(CONTENT_OBJECT, py_co)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CObject as args");
		return NULL;
	}

	if (py_parsed_co != Py_None) {
		if (!CCNObject_IsValid(PARSED_CONTENT_OBJECT, py_parsed_co)
				|| !CCNObject_IsValid(CONTENT_OBJECT_COMPONENTS,
				py_co_components)) {
			PyErr_SetString(PyExc_TypeError, "Second and third arguments need"
					" to be PCO and CO_COMPS");
			return NULL;
		}

		return ContentObject_from_ccn_parsed(
				CCNObject_Get(CONTENT_OBJECT, py_co),
				CCNObject_Get(PARSED_CONTENT_OBJECT, py_parsed_co),
				CCNObject_Get(CONTENT_OBJECT_COMPONENTS, py_co_components));
	}

	return ContentObject_from_ccn(CCNObject_Get(CONTENT_OBJECT, py_co));

}
#endif
