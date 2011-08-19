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

		py_component = PyByteArray_FromStringAndSize((char *) component, size);
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
		if (PyByteArray_Check(item)) {
			Py_ssize_t n = PyByteArray_Size(item);
			char *b = PyByteArray_AsString(item);
			r = ccn_name_append(name, b, n);
			JUMP_IF_NEG_MEM(r, error);
		} else if (PyString_Check(item)) { // Unicode or UTF-8?
			char *s = PyString_AsString(item);
			JUMP_IF_NULL(s, error);

			r = ccn_name_append_str(name, s);
			JUMP_IF_NEG_MEM(r, error);

			// Note, we choose to convert numbers to their string
			// representation; if we want numeric encoding, use a
			// byte array and do it explicitly.
		} else if (PyFloat_Check(item) || PyLong_Check(item) || PyInt_Check(item)) {
			PyObject *str = PyObject_Str(item);
			JUMP_IF_NULL(str, error);

			char *s = PyString_AsString(str);
			if (!s) {
				Py_DECREF(str);
				goto error;
			}

			r = ccn_name_append_str(name, s);
			Py_DECREF(str);
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
Name_from_ccn_parsed(PyObject *py_content_object,
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

	py_Name = Name_from_ccn(py_ccn_name);
	Py_DECREF(py_ccn_name);

	return py_Name;
}

PyObject *
Name_from_ccn(PyObject *py_cname)
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
		} else if (PyString_Check(item)) { // Unicode or UTF-8?
			char *s = PyString_AsString(item);
			JUMP_IF_NULL(s, error);

			r = ccn_name_append_str(name, s);
			JUMP_IF_NEG_MEM(r, error);

			// Note, we choose to convert numbers to their string
			// representation; if we want numeric encoding, use a
			// byte array and do it explicitly.
		} else if (PyFloat_Check(item) || PyLong_Check(item) || PyInt_Check(item)) {
			PyObject *str = PyObject_Str(item);
			JUMP_IF_NULL(str, error);

			char *s = PyString_AsString(str);
			if (!s) {
				Py_DECREF(str);
				goto error;
			}

			r = ccn_name_append_str(name, s);
			Py_DECREF(str);
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
	py_name = r < 0 ? PyErr_NoMemory() : Name_from_ccn(py_cname);
	Py_DECREF(py_cname);

	return py_name;
}
