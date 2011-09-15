/*
 * Copyright (c) 2011, Regents of the University of California
 * All rights reserved.
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
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

#include "python_hdr.h"
#include <ccn/ccn.h>
#include <ccn/uri.h>

#include "methods_name.h"
#include "pyccn.h"
#include "objects.h"
#include "util.h"

// Can be called directly from c library
// For now, everything is a bytearray

static PyObject *
name_comps_from_ccn(PyObject *py_cname)
{
	struct ccn_charbuf *name;
	struct ccn_indexbuf *comp_index;
	int r;
	PyObject *py_component_list = NULL, *py_component;

	assert(CCNObject_IsValid(NAME, py_cname));

	name = CCNObject_Get(NAME, py_cname);

	comp_index = ccn_indexbuf_create();
	JUMP_IF_NULL_MEM(comp_index, error);

	r = ccn_name_split(name, comp_index);
	if (r < 0) {
		PyErr_SetString(PyExc_TypeError, "The argument is not a valid CCN"
				" name");
		goto error;
	}

	// Create component list
	py_component_list = PyList_New(0);
	JUMP_IF_NULL(py_component_list, error);

	/* I wish I could understand this code -dk */
	for (size_t n = 0; n < comp_index->n - 1; n++) { // not the implicit digest component
		size_t h; // header size
		int size;
		unsigned char *component;

		debug("name_comps_from_ccn component %d of %d \n", n, comp_index->n - 2);

		component = &(name->buf[comp_index->buf[n]]) + 1; // What is the first byte? (250?)
		//debug("\t%s\n", component);

		for (h = 2; h < (comp_index->buf[n + 1] - comp_index->buf[n]); h++) { // walk through the header until the terminators is found
			if (*(component++) > 127)
				break;
		}

		size = (comp_index->buf[n + 1] - comp_index->buf[n]) - 1 - h; // don't include the DTAG Component

		py_component = PyBytes_FromStringAndSize((char *) component, size);
		JUMP_IF_NULL(py_component, error);

		r = PyList_Append(py_component_list, py_component);
		Py_DECREF(py_component);
		JUMP_IF_NEG(r, error);
	}
	// TODO: Add implicit digest component?
	// TODO: Parse version & segment?

	ccn_indexbuf_destroy(&comp_index);

	return py_component_list;

error:
	ccn_indexbuf_destroy(&comp_index);
	Py_XDECREF(py_component_list);
	return NULL;
}

PyObject *
_pyccn_Name_to_ccn(PyObject *UNUSED(self), PyObject *py_name_components)
{
	struct ccn_charbuf *name;
	PyObject *py_name, *iterator, *item = NULL;
	PyObject *py_o;
	int r;

	if (!PyList_Check(py_name_components)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a components of the Name");
		return NULL;
	}

	iterator = PyObject_GetIter(py_name_components);
	if (!iterator)
		return NULL;

	py_name = CCNObject_New_charbuf(NAME, &name);
	JUMP_IF_NULL(name, error);

	r = ccn_name_init(name);
	JUMP_IF_NEG_MEM(r, error);

	// Parse the list of components and
	// convert them to C objects
	//
	while ((item = PyIter_Next(iterator))) {
		if (PyUnicode_Check(item)) {
			char *s;
			Py_ssize_t len;

			py_o = _pyccn_unicode_to_utf8(item, &s, &len);
			JUMP_IF_NULL(py_o, error);

			r = ccn_name_append(name, s, len);
			Py_DECREF(py_o);
			JUMP_IF_NEG_MEM(r, error);
		} else if (PyBytes_Check(item)) {
			char *b;
			Py_ssize_t n;

			r = PyBytes_AsStringAndSize(item, &b, &n);
			JUMP_IF_NEG(r, error);

			r = ccn_name_append(name, b, n);
			JUMP_IF_NEG_MEM(r, error);
		} else if (PyByteArray_Check(item)) {
			Py_ssize_t n = PyByteArray_Size(item);
			char *b = PyByteArray_AsString(item);
			r = ccn_name_append(name, b, n);
			JUMP_IF_NEG_MEM(r, error);

			// Note, we choose to convert numbers to their string
			// representation; if we want numeric encoding, use a
			// byte array and do it explicitly.
		} else if (PyFloat_Check(item) || PyLong_Check(item) ||
				_pyccn_Int_Check(item)) {
			char *s;
			PyObject *py_o2;

			py_o = PyObject_Str(item);
			JUMP_IF_NULL(py_o, error);

			py_o2 = _pyccn_unicode_to_utf8(py_o, &s, NULL);
			Py_DECREF(py_o);
			if (!py_o2)
				goto error;

			r = ccn_name_append_str(name, s);
			Py_DECREF(py_o2);
			JUMP_IF_NEG_MEM(r, error);
		} else {
			PyErr_SetString(PyExc_TypeError, "Unknown value type in the list");
			goto error;
		}
		Py_DECREF(item);
	}
	Py_CLEAR(iterator);

	return CCNObject_New(NAME, name);

error:
	Py_XDECREF(item);
	Py_DECREF(iterator);
	Py_XDECREF(py_name);
	return NULL;
}

// From within python
//

PyObject *
_pyccn_Name_from_ccn(PyObject *UNUSED(self), PyObject *py_cname)
{
	if (!CCNObject_IsValid(NAME, py_cname)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN name");
		return NULL;
	}

	return name_comps_from_ccn(py_cname);
}

PyObject *
Name_obj_from_ccn(PyObject *py_cname)
{
	PyObject *py_Name = NULL, *py_components;
	int r;

	assert(g_type_Name);
	assert(CCNObject_IsValid(NAME, py_cname));

	py_Name = PyObject_CallObject(g_type_Name, NULL);
	JUMP_IF_NULL(py_Name, error);

	py_components = name_comps_from_ccn(py_cname);
	JUMP_IF_NULL(py_components, error);

	r = PyObject_SetAttrString(py_Name, "components", py_components);
	Py_DECREF(py_components);
	JUMP_IF_NEG(r, error);

	r = PyObject_SetAttrString(py_Name, "ccn_data", py_cname);
	JUMP_IF_NEG(r, error);

	return py_Name;

error:
	Py_XDECREF(py_Name);
	return NULL;
}

PyObject *
Name_to_ccn(PyObject *py_obj_Name)
{
	struct ccn_charbuf *name;
	PyObject *py_o;
	PyObject *py_name = NULL;
	PyObject *comps, *iterator, *item = NULL;
	int r;

	comps = PyObject_GetAttrString(py_obj_Name, "components");
	if (!comps)
		return NULL;

	iterator = PyObject_GetIter(comps);
	Py_DECREF(comps);
	if (!iterator)
		return NULL;

	py_name = CCNObject_New_charbuf(NAME, &name);
	JUMP_IF_NULL(py_name, error);

	r = ccn_name_init(name);
	JUMP_IF_NEG_MEM(r, error);

	// Parse the list of components and
	// convert them to C objects
	//
	while ((item = PyIter_Next(iterator))) {
		if (PyByteArray_Check(item)) {
			char *b = PyByteArray_AsString(item);
			Py_ssize_t n = PyByteArray_GET_SIZE(item);
			r = ccn_name_append(name, b, n);
			JUMP_IF_NEG_MEM(r, error);
		} else if (_pyccn_STRING_CHECK(item)) {
			char *s;
			Py_ssize_t len;

			py_o = _pyccn_unicode_to_utf8(item, &s, &len);
			JUMP_IF_NULL(py_o, error);

			r = ccn_name_append(name, s, len);
			Py_DECREF(py_o);
			JUMP_IF_NEG_MEM(r, error);

			// Note, we choose to convert numbers to their string
			// representation; if we want numeric encoding, use a
			// byte array and do it explicitly.
		} else if (PyFloat_Check(item) || PyLong_Check(item) ||
				_pyccn_Int_Check(item)) {
			char *s;

			py_o = PyObject_Str(item);
			JUMP_IF_NULL(py_o, error);

			/* Since it is a number no UTF8 needed */
			s = PyBytes_AS_STRING(py_o);
			if (!s) {
				Py_DECREF(py_o);
				goto error;
			}

			r = ccn_name_append_str(name, s);
			Py_DECREF(py_o);
			JUMP_IF_NEG_MEM(r, error);
		} else {
			PyErr_SetString(PyExc_TypeError, "Unknown value type in the list");
			goto error;
		}
		Py_DECREF(item);
	}
	Py_DECREF(iterator);

	return py_name;

error:
	Py_XDECREF(item);
	Py_XDECREF(py_name);
	Py_XDECREF(iterator);

	return NULL;
}

// Takes a byte array with DTAG
//

PyObject *
Name_from_ccn_tagged_bytearray(const unsigned char *buf, size_t size)
{
	PyObject *py_name, *py_cname;
	struct ccn_charbuf *name;
	int r;

	name = ccn_charbuf_create();
	if (!name)
		return PyErr_NoMemory();

	py_cname = CCNObject_New(NAME, name);
	if (!py_cname) {
		ccn_charbuf_destroy(&name);
		return NULL;
	}

	r = ccn_charbuf_append(name, buf, size);
	py_name = r < 0 ? PyErr_NoMemory() : Name_obj_from_ccn(py_cname);
	Py_DECREF(py_cname);

	return py_name;
}

PyObject *
_pyccn_name_from_uri(PyObject *UNUSED(self), PyObject *py_uri)
{
	struct ccn_charbuf *name;
	PyObject *py_name = NULL, *py_o;
	char *buf;
	int r;

	if (!_pyccn_STRING_CHECK(py_uri)) {
		PyErr_SetString(PyExc_TypeError, "Expected string");
		return NULL;
	}

	py_name = CCNObject_New_charbuf(NAME, &name);
	JUMP_IF_NULL(py_name, error);

	py_o = _pyccn_unicode_to_utf8(py_uri, &buf, NULL);
	JUMP_IF_NULL(py_o, error);

	r = ccn_name_from_uri(name, buf);
	Py_DECREF(py_o);
	if (r < 0) {
		PyErr_SetString(g_PyExc_CCNNameError, "Error parsing URI");
		goto error;
	}

	return py_name;

error:
	Py_XDECREF(py_name);
	return NULL;
}

PyObject *
_pyccn_name_to_uri(PyObject *UNUSED(self), PyObject *py_name)
{
	struct ccn_charbuf *cb, *uri = NULL;
	enum _pyccn_capsules type;
	int r;
	PyObject *py_o;

	if (CCNObject_IsValid(NAME, py_name)) {
		type = NAME;
		goto correct_type;
	}

	/*
		if (CCNObject_IsValid(INTEREST, py_name)) {
			type = INTEREST;
			goto correct_type;
		}

		if (CCNObject_IsValid(CONTENT_OBJECT, py_name)) {
			type = CONTENT_OBJECT;
			goto correct_type;
		}
	 */

	PyErr_SetString(PyExc_TypeError, "Expected CCN name");
	return NULL;

correct_type:
	cb = CCNObject_Get(type, py_name);

	uri = ccn_charbuf_create();
	JUMP_IF_NULL_MEM(uri, error);

	r = ccn_uri_append(uri, cb->buf, cb->length, 0);
	if (r < 0) {
		PyErr_SetString(g_PyExc_CCNNameError, "Error while converting name");
		goto error;
	}

	py_o = PyUnicode_FromStringAndSize((char *) uri->buf, uri->length);
	ccn_charbuf_destroy(&uri);
	JUMP_IF_NULL(py_o, error);

	return py_o;

error:
	ccn_charbuf_destroy(&uri);
	return NULL;
}

PyObject *
_pyccn_compare_names(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_name1, *py_name2;
	struct ccn_charbuf *name1, *name2;
	int diff;

	if (!PyArg_ParseTuple(args, "OO", &py_name1, &py_name2))
		return NULL;

	if (!CCNObject_IsValid(NAME, py_name1)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN name as 1st"
				" argument");
		return NULL;
	}

	if (!CCNObject_IsValid(NAME, py_name2)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN name as 2nd"
				" argument");
		return NULL;
	}

	name1 = CCNObject_Get(NAME, py_name1);
	name2 = CCNObject_Get(NAME, py_name2);

	diff = ccn_compare_names(name1->buf, name1->length, name2->buf,
			name2->length);

	return Py_BuildValue("i", diff);
}
