/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#include "python_hdr.h"
#include <ccn/ccn.h>

#include "pyccn.h"
#include "methods_key.h"
#include "methods_name.h"
#include "methods_signature.h"
#include "methods_signedinfo.h"
#include "objects.h"
#include "util.h"

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

	py_content = PyBytes_FromStringAndSize(value, size);
	if (!py_content)
		return NULL;

	return py_content;
}

static PyObject *
Name_obj_from_ccn_parsed(PyObject *py_content_object,
		PyObject *py_parsed_content_object)
{
	struct ccn_charbuf *content_object;
	struct ccn_parsed_ContentObject *parsed_content_object;
	PyObject *py_ccn_name;
	PyObject *py_Name;
	struct ccn_charbuf *name;
	size_t name_begin, name_end, s;
	int r;

	assert(CCNObject_IsValid(CONTENT_OBJECT, py_content_object));
	assert(CCNObject_IsValid(PARSED_CONTENT_OBJECT, py_parsed_content_object));

	content_object = CCNObject_Get(CONTENT_OBJECT, py_content_object);
	parsed_content_object = CCNObject_Get(PARSED_CONTENT_OBJECT,
			py_parsed_content_object);

	name_begin = parsed_content_object->offset[CCN_PCO_B_Name];
	name_end = parsed_content_object->offset[CCN_PCO_E_Name];
	s = name_end - name_begin;

	debug("ContentObject_from_ccn_parsed Name len=%zd\n", s);
	if (parsed_content_object->name_ncomps <= 0) {
		PyErr_SetString(g_PyExc_CCNNameError, "No name stored (or name is"
				" invalid) in parsed content object");
		return NULL;
	}

	py_ccn_name = CCNObject_New_charbuf(NAME, &name);
	if (!py_ccn_name)
		return NULL;

	r = ccn_charbuf_append(name, &content_object->buf[name_begin], s);
	if (r < 0) {
		Py_DECREF(py_ccn_name);
		return PyErr_NoMemory();
	}

#if DEBUG_MSG
	debug("Name: ");
	dump_charbuf(name, stderr);
	debug("\n");
#endif

	py_Name = Name_obj_from_ccn(py_ccn_name);
	Py_DECREF(py_ccn_name);

	return py_Name;
}

// ** Methods of ContentObject
//
// Content Objects

PyObject *
ContentObject_obj_from_ccn_parsed(PyObject *py_content_object,
		PyObject *py_parsed_content_object, PyObject *py_components)
{
	struct ccn_charbuf *content_object;
	struct ccn_parsed_ContentObject *parsed_content_object;
	PyObject *py_obj_ContentObject, *py_o;
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

	py_obj_ContentObject = PyObject_CallObject(g_type_ContentObject, NULL);
	if (!py_obj_ContentObject)
		return NULL;

	/* Name */
	py_o = Name_obj_from_ccn_parsed(py_content_object, py_parsed_content_object);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_ContentObject, "name", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	/* Content */
	py_o = Content_from_ccn_parsed(content_object, parsed_content_object);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_ContentObject, "content", py_o);
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
	r = PyObject_SetAttrString(py_obj_ContentObject, "signature", py_o);
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
	r = PyObject_SetAttrString(py_obj_ContentObject, "signedInfo", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	debug("ContentObject_from_ccn_parsed DigestAlgorithm\n");
	// TODO...  Note this seems to default to nothing in the library...?
	r = PyObject_SetAttrString(py_obj_ContentObject, "digestAlgorithm", Py_None);
	JUMP_IF_NEG(r, error);

	/* Original data  */
	debug("ContentObject_from_ccn_parsed ccn_data\n");
	r = PyObject_SetAttrString(py_obj_ContentObject, "ccn_data", py_content_object);
	JUMP_IF_NEG(r, error);

	debug("ContentObject_from_ccn_parsed ccn_data_parsed\n");
	r = PyObject_SetAttrString(py_obj_ContentObject, "ccn_data_parsed",
			py_parsed_content_object);
	JUMP_IF_NEG(r, error);

	debug("ContentObject_from_ccn_parsed ccn_data_components\n");
	r = PyObject_SetAttrString(py_obj_ContentObject, "ccn_data_components",
			py_components);
	JUMP_IF_NEG(r, error);

#pragma message "XXX: Test code if it works without setting ccn_data_dirty=False"
	r = PyObject_SetAttrString(py_obj_ContentObject, "ccn_data_dirty", Py_False);
	JUMP_IF_NEG(r, error);

	debug("ContentObject_from_ccn_parsed complete\n");

	return py_obj_ContentObject;

error:
	Py_XDECREF(py_obj_ContentObject);
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
	PyObject* CO = ContentObject_obj_from_ccn_parsed(content_object, parsed_content_object, components);
	free(parsed_content_object);
	ccn_indexbuf_destroy(&components);
	return CO;
}
#endif

PyObject *
_pyccn_content_to_bytearray(PyObject *UNUSED(self), PyObject *arg)
{
	PyObject *str, *result;

	if (arg == Py_None)
		Py_RETURN_NONE;
	else if (PyFloat_Check(arg) || PyLong_Check(arg) || _pyccn_Int_Check(arg)) {
		PyObject *py_o;

		py_o = PyObject_Str(arg);
		if (!py_o)
			return NULL;

#if PY_MAJOR_VERSION >= 3
		str = PyUnicode_EncodeUTF8(PyUnicode_AS_UNICODE(py_o),
				PyUnicode_GET_SIZE(py_o), NULL);
		Py_DECREF(py_o);
#else
		str = py_o;
#endif
	} else if (PyUnicode_Check(arg)) {
		str = PyUnicode_EncodeUTF8(PyUnicode_AS_UNICODE(arg),
				PyUnicode_GET_SIZE(arg), NULL);
	} else
		str = (Py_INCREF(arg), arg);

	if (!str)
		return NULL;

	result = PyByteArray_FromObject(str);
	Py_DECREF(str);

	return result;
}

PyObject *
_pyccn_content_to_bytes(PyObject *UNUSED(self), PyObject *arg)
{
	PyObject *str;

	if (arg == Py_None)
		Py_RETURN_NONE;
	else if (PyFloat_Check(arg) || PyLong_Check(arg) || _pyccn_Int_Check(arg)) {
		PyObject *py_o;

		py_o = PyObject_Str(arg);
		if (!py_o)
			return NULL;

#if PY_MAJOR_VERSION >= 3
		str = PyUnicode_EncodeUTF8(PyUnicode_AS_UNICODE(py_o),
				PyUnicode_GET_SIZE(py_o), NULL);
		Py_DECREF(py_o);
#else
		str = py_o;
#endif
		return str;
	} else if (PyUnicode_Check(arg))
		return PyUnicode_EncodeUTF8(PyUnicode_AS_UNICODE(arg),
			PyUnicode_GET_SIZE(arg), NULL);

	return PyObject_Bytes(arg);
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
	Py_ssize_t content_len;
	int r;

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

	if (py_content != Py_None && !PyBytes_Check(py_content)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Bytes as arg 3");
		return NULL;
	} else if (py_content == Py_None) {
		content = NULL;
		content_len = 0;
	} else {
		r = PyBytes_AsStringAndSize(py_content, &content, &content_len);
		if (r < 0)
			return NULL;
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

PyObject *
_pyccn_ContentObject_from_ccn(PyObject *UNUSED(self), PyObject *py_co)
{
	struct ccn_charbuf *co;
	PyObject *res = NULL;
	int r;
	PyObject *py_pco = NULL;
	struct ccn_parsed_ContentObject *pco;
	PyObject *py_comps = NULL;
	struct ccn_indexbuf *comps;

	if (!CCNObject_IsValid(CONTENT_OBJECT, py_co)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN ContentObject as args");
		return NULL;
	}
	co = CCNObject_Get(CONTENT_OBJECT, py_co);

	py_pco = CCNObject_New_ParsedContentObject(&pco);
	JUMP_IF_NULL(py_pco, exit);

	py_comps = CCNObject_New_ContentObjectComponents(&comps);
	JUMP_IF_NULL(py_comps, exit);

	r = ccn_parse_ContentObject(co->buf, co->length, pco, comps);
	if (r < 0) {
		PyErr_SetString(g_PyExc_CCNContentObjectError, "Error parsing Content"
				" Object");
		goto exit;
	}

	res = ContentObject_obj_from_ccn_parsed(py_co, py_pco, py_comps);

exit:
	Py_XDECREF(py_comps);
	Py_XDECREF(py_pco);
	return res;
}

PyObject *
_pyccn_digest_contentobject(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_content_object, *py_parsed_content_object;
	struct ccn_charbuf *content_object;
	struct ccn_parsed_ContentObject *parsed_content_object;
	PyObject *py_digest;

	if (!PyArg_ParseTuple(args, "OO", &py_content_object,
			&py_parsed_content_object))
		return NULL;

	if (!CCNObject_IsValid(CONTENT_OBJECT, py_content_object)) {
		PyErr_SetString(PyExc_TypeError, "Expected CCN ContentObject");
		return NULL;
	}

	if (!CCNObject_IsValid(PARSED_CONTENT_OBJECT, py_parsed_content_object)) {
		PyErr_SetString(PyExc_TypeError, "Expected CCN parsed ContentObject");
		return NULL;
	}

	content_object = CCNObject_Get(CONTENT_OBJECT, py_content_object);
	parsed_content_object = CCNObject_Get(PARSED_CONTENT_OBJECT,
			py_parsed_content_object);

	/*
	 * sanity check (sigh, I guess pco and comps should be carried in
	 * capsule's context, since they're very closely related)
	 */
	if (content_object->length != parsed_content_object->offset[CCN_PCO_E]) {
		PyErr_SetString(PyExc_ValueError, "ContentObject size doesn't match"
				" the size reported by pco");
		return NULL;
	}

	ccn_digest_ContentObject(content_object->buf, parsed_content_object);
	py_digest = PyBytes_FromStringAndSize(
			(char *) parsed_content_object->digest,
			parsed_content_object->digest_bytes);

	return py_digest;
}

PyObject *
_pyccn_content_matches_interest(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_content_object, *py_pco = Py_None, *py_interest,
			*py_pi = Py_None;
	struct ccn_charbuf *content_object, *interest;
	struct ccn_parsed_ContentObject *pco = NULL;
	struct ccn_parsed_interest *pi = NULL;
	int r;
	PyObject *res;

	if (!PyArg_ParseTuple(args, "OO|OO", &py_content_object, &py_interest,
			&py_pco, &py_pi))
		return NULL;

	if (!CCNObject_IsValid(CONTENT_OBJECT, py_content_object)) {
		PyErr_SetString(PyExc_TypeError, "Expected CCN ContentObject");
		return NULL;
	}
	content_object = CCNObject_Get(CONTENT_OBJECT, py_content_object);

	if (!CCNObject_IsValid(INTEREST, py_interest)) {
		PyErr_SetString(PyExc_TypeError, "Expected CCN Interest");
		return NULL;
	}
	interest = CCNObject_Get(INTEREST, py_interest);

	if (py_pco != Py_None) {
		if (!CCNObject_IsValid(PARSED_CONTENT_OBJECT, py_pco)) {
			PyErr_SetString(PyExc_TypeError,
					"Expected CCN Parsed ContentObject");
			return NULL;
		}
		pco = CCNObject_Get(PARSED_CONTENT_OBJECT, py_pco);
	}

	if (py_pi != Py_None) {
		if (!CCNObject_IsValid(PARSED_INTEREST, py_pi)) {
			PyErr_SetString(PyExc_TypeError, "Expected CCN Parsed Interest");
			return NULL;
		}
		pi = CCNObject_Get(PARSED_INTEREST, py_pi);
	}

	r = ccn_content_matches_interest(content_object->buf,
			content_object->length, 1, pco, interest->buf, interest->length,
			pi);

	res = r ? Py_True : Py_False;

	return Py_INCREF(res), res;
}
