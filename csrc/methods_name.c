#include <Python.h>
#include <ccn/ccn.h>

#include "methods_name.h"
#include "pyccn.h"
#include "misc.h"
#include "objects.h"

// Naming

PyObject *
_pyccn_Name_to_ccn(PyObject *self, PyObject *py_name_components)
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

	py_name = CCNObject_New_Name(&name);
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
_pyccn_Name_from_ccn(PyObject *self, PyObject *py_cname)
{
	PyObject *py_component_list = NULL, *py_component = NULL;
	struct ccn_charbuf *name;
	struct ccn_indexbuf *comp_index;
	int r;

	if (!CCNObject_IsValid(NAME, py_cname)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN name");
		return NULL;
	}
	name = CCNObject_Get(NAME, py_cname);

	debug("Name_from_ccn start\n");

	// Iterate through name components
	// Copy into byte array
	comp_index = ccn_indexbuf_create();
	JUMP_IF_NULL_MEM(comp_index, error);

	r = ccn_name_split(name, comp_index);
	if (r < 0) {
		PyErr_SetString(PyExc_TypeError, "The argument is not a valid CCN name");
		goto error;
	}

	// Create component list
	py_component_list = PyList_New(0);
	JUMP_IF_NULL(py_component_list, error);

	/* I wish I could understand this code -dk */
	unsigned char *component;
	int size;
	int n; // component
	int h; // header size
	for (n = 0; n < comp_index->n - 1; n++) { // not the implicit digest component
		debug("Name_from_ccn component %d of %d \n", n, comp_index->n - 2);

		component = &(name->buf[comp_index->buf[n]]) + 1; // What is the first byte? (250?)
		//debug("\t%s\n", component);

		for (h = 2; h < (comp_index->buf[n + 1] - comp_index->buf[n]); h++) { // walk through the header until the terminators is found
			if (*(component++) > 127)
				break;
		}

		size = (int) (comp_index->buf[n + 1] - comp_index->buf[n]) - 1 - h; // don't include the DTAG Component

		py_component = PyByteArray_FromStringAndSize((char*) component, size);
		JUMP_IF_NULL(py_component, error);

		r = PyList_Append(py_component_list, py_component);
		Py_DECREF(py_component);
		JUMP_IF_NEG(r, error);
	}
	// TODO: Add implicit digest componet?
	// TODO: Parse version & segment?

	ccn_indexbuf_destroy(&comp_index);

	debug("Name_from_ccn ends\n");
	return py_component_list;

error:
	ccn_indexbuf_destroy(&comp_index);
	Py_XDECREF(py_component_list);
	return NULL;
}

PyObject *
Name_from_ccn_parsed(struct ccn_charbuf *content_object,
		struct ccn_parsed_ContentObject *parsed_content_object)
{
	PyObject *py_Name;
	size_t namelen;
	int r;

	namelen = parsed_content_object->offset[CCN_PCO_E_Name]
			- parsed_content_object->offset[CCN_PCO_B_Name];

	debug("ContentObject_from_ccn_parsed Name len=%zd\n", namelen);
	if (namelen > 0) {
		struct ccn_charbuf *name;
		size_t name_begin, name_end;
		PyObject *py_ccn_name;

		name = ccn_charbuf_create();
		if (!name)
			return PyErr_NoMemory();

		py_ccn_name = CCNObject_New(NAME, name);
		if (!py_ccn_name) {
			ccn_charbuf_destroy(&name);
			return NULL;
		}

		name_begin = parsed_content_object->offset[CCN_PCO_B_Name];
		name_end = parsed_content_object->offset[CCN_PCO_E_Name];

		r = ccn_charbuf_append(name, &content_object->buf[name_begin],
				name_end - name_begin);
		if (r < 0) {
			Py_DECREF(py_ccn_name);
			return PyErr_NoMemory();
		}

		debug("Name: ");
		dump_charbuf(name, stderr);
		debug("\n");

		py_Name = Name_from_ccn(py_ccn_name);
		Py_DECREF(py_ccn_name);
	} else {
		PyErr_SetString(g_PyExc_CCNNameError, "No name stored (or name is"
				" invalid) in parsed content object");
		return NULL;
	}

	return py_Name;
}

// Can be called directly from c library
// For now, everything is a bytearray
//

//XXX: Rewrite

PyObject *
Name_from_ccn(PyObject *ccn_data)
{
	struct ccn_charbuf *name;

	debug("Name_from_ccn start\n");

	// Create name object
	PyObject* py_name = PyObject_CallObject(g_type_Name, NULL);

	// Create component list
	PyObject* py_component_list = PyList_New(0);
	PyObject_SetAttrString(py_name, "components", py_component_list);

	// Iterate through name components
	// Copy into byte array
	PyObject* py_component;

	struct ccn_indexbuf* comps = ccn_indexbuf_create();
	name = CCNObject_Get(NAME, ccn_data);
	ccn_name_split(name, comps);

	unsigned char* comp;
	int size;
	int n; // component
	int h; // header size
	for (n = 0; n < comps->n - 1; n++) { // not the implicit digest component
		fprintf(stderr, "Name_from_ccn component %d of %d \n", n, n < comps->n - 1);
		comp = &(name->buf[comps->buf[n]]) + 1; // What is the first byte?  (250?)
		//fprintf(stderr,"\t%s\n", comp);
		for (h = 2; h < (comps->buf[n + 1] - comps->buf[n]); h++) { // walk through the header until the terminators is found
			if (*(comp++) > 127) break;
		}
		size = (int) (comps->buf[n + 1] - comps->buf[n]) - 1 - h; // don't include the DTAG Component
		py_component = PyByteArray_FromStringAndSize((char*) comp, size);
		PyList_Append(py_component_list, py_component);
		Py_DECREF(py_component);
	}
	// TODO: Add implicit digest componet?
	// TODO: Parse version & segment?

	PyObject_SetAttrString(py_name, "ccn_data", ccn_data);

	ccn_indexbuf_destroy(&comps);

	fprintf(stderr, "Name_from_ccn ends\n");
	return py_name;
}

struct ccn_charbuf *
Name_to_ccn(PyObject *py_name)
{
	struct ccn_charbuf *name;
	PyObject *comps, *iterator, *item = NULL;
	int r;

	comps = PyObject_GetAttrString(py_name, "components");
	if (!comps)
		return NULL;

	iterator = PyObject_GetIter(comps);
	Py_DECREF(comps);
	if (!iterator)
		return NULL;

	name = ccn_charbuf_create();
	JUMP_IF_NULL(name, out_of_mem);

	r = ccn_name_init(name);
	JUMP_IF_NEG(r, out_of_mem);

	// Parse the list of components and
	// convert them to C objects
	//
	while ((item = PyIter_Next(iterator))) {
		if (PyByteArray_Check(item)) {
			Py_ssize_t n = PyByteArray_Size(item);
			char *b = PyByteArray_AsString(item);
			r = ccn_name_append(name, b, n);
			JUMP_IF_NEG(r, out_of_mem);
		} else if (PyString_Check(item)) { // Unicode or UTF-8?
			char *s = PyString_AsString(item);
			JUMP_IF_NULL(s, error);

			r = ccn_name_append_str(name, s);
			JUMP_IF_NEG(r, out_of_mem);

			// Note, we choose to convert numbers to their string
			// representation; if we want numeric encoding, use a
			// byte array and do it explicitly.
		} else if (PyFloat_Check(item) || PyLong_Check(item) || PyInt_Check(item)) {
			PyObject *str = PyObject_Str(item);
			JUMP_IF_NULL(str, error);

			char *s = PyString_AsString(str);
			Py_DECREF(str);
			JUMP_IF_NULL(s, error);

			r = ccn_name_append_str(name, s);
			JUMP_IF_NEG(r, out_of_mem);
		} else {
			PyErr_SetString(PyExc_TypeError, "Unknown value type in the list");
			goto error;
		}
		Py_DECREF(item);
	}
	Py_DECREF(iterator);

	return name;

out_of_mem:
	PyErr_SetNone(PyExc_MemoryError);
error:
	Py_XDECREF(item);
	Py_XDECREF(iterator);
	ccn_charbuf_destroy(&name);
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
