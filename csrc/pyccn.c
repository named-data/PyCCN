//
//  Python bindings for CCNx
//  jburke@ucla.edu
//  6/27/2011
//
//  (C) 2011 Regents of the University of California
//  Unreleased...
//
//

// This is intended to be a rather "thin" implementation, which supports
// Python objects corresponding to the major CCNx entities - Interest, ContentObject,
// and so on, as well as some support objects.  The C code is mostly just
// responsible for marshaling data back and forth between the formats, though
// there are some useful functions for key generation/access included.
//
// These are mapped more or less directly from the CCNx wire format, and the
// Python objects are, in fact, backed by a cached version of the wire format
// or native c object, a Python CObject kept in self.ccn_data. Accessing the
// attribute regenerates this backing CObject if necessary - those mechanics
// are in the Python code.
//
// The Interest and ContentObject objects also cache their parsed versions
// as well
//
//

// So far this is being built with Eclipse compiling on Mac OS X 10.6.6
// Using Apple's version of Python 2.6.1.  It should under other versions
// if things are compiled against the right headers.
// Link to a shared library (.so).
//

// Still left to do:
// - Finish implementing ccn library calls of interest (stubs below)
// - Fill in help text python method declaration
// - Error checking and exception handling
// - Check proper use of Py_INCREF and Py_DECREF macros.
// - Update for new key functions in the current branch Nick B has
// - Unit test and debug against C and Java APIs
// - Buffer overflow protection?
// - Lots of interesting high-level stuff in Python may require new support code here.

// Long-term:
// - Most key- and signing-related functions are hardcoded
//   for RSA and SHA256 because the wire format and/or libraries
//   provide no other examples.  Need to keep an eye on API support
//   and update.

#include <Python.h>
#include <ccn/ccn.h>
#include <ccn/hashtb.h>
#include <ccn/uri.h>
#include <ccn/signing.h>

#include <stdbool.h>

#include "pyccn.h"
#include "converters.h"
#include "key_utils.h"
#include "methods.h"
#include "misc.h"

// Primary types for the Python libraries,
// taken directly from the CCNx wire format
//
PyObject *g_type_Name;
static PyObject *g_type_CCN;
PyObject *g_type_Interest;
PyObject *g_type_ContentObject;
static PyObject *g_type_Closure;
PyObject *g_type_Key;

// Plus some secondary helper types, which
// are declared as inner classes.
//
PyObject *g_type_ExclusionFilter;
PyObject *g_type_KeyLocator;
PyObject *g_type_Signature;
PyObject *g_type_SignedInfo;
PyObject *g_type_SigningParams;
PyObject *g_type_UpcallInfo;

// Exceptions
PyObject *g_PyExc_CCNError;
PyObject *g_PyExc_CCNNameError;


void
__ccn_closure_destroy(void *p)
{
	if (p != NULL)
		free(p);
}

static bool
import_module(PyObject **module, const char *name)
{
	assert(module);
	assert(name);

	*module = PyImport_ImportModule(name);
	if (*module)
		return true;

	fprintf(stderr, "Unable to import %s\n", name);

	return false;
}

PyMODINIT_FUNC
init_pyccn(void)
{
	PyObject *module;
	PyObject *module_Name, *module_CCN, *module_Interest;
	PyObject *module_ContentObject, *module_Closure, *module_Key;

	module = initialize_methods("pyccn._pyccn");
	if (!module) {
		fprintf(stderr, "Unable to initialize PyCCN module\n");
		return;
	}

	/* General CCN Exceptions */
	g_PyExc_CCNError = PyErr_NewExceptionWithDoc("_pyccn.CCNError",
		"Generic CCN Exception", NULL, NULL);
	Py_INCREF(g_PyExc_CCNError);
	PyModule_AddObject(module, "CCNError", g_PyExc_CCNError);

	g_PyExc_CCNNameError = PyErr_NewExceptionWithDoc("_pyccn.CCNNameError",
		"Name exception", g_PyExc_CCNError, NULL);
	Py_INCREF(g_PyExc_CCNNameError);
	PyModule_AddObject(module, "CCNNameError", g_PyExc_CCNNameError);

	if (!import_module(&module_CCN, "pyccn.CCN"))
		return; //XXX: How to uninitialize methods?

	if (!import_module(&module_Interest, "pyccn.Interest"))
		goto unload_ccn;

	if (!import_module(&module_ContentObject, "pyccn.ContentObject"))
		goto unload_contentobject;

	if (!import_module(&module_Closure, "pyccn.Closure"))
		goto unload_closure;

	if (!import_module(&module_Key, "pyccn.Key"))
		goto unload_key;

	if (!import_module(&module_Name, "pyccn.Name"))
		goto unload_name;

	/*
		PyObject *CCNDict = PyModule_GetDict(g_module_CCN);
	 */
	PyObject *InterestDict = PyModule_GetDict(module_Interest);
	PyObject *ContentObjectDict = PyModule_GetDict(module_ContentObject);
	PyObject *ClosureDict = PyModule_GetDict(module_Closure);
	PyObject *KeyDict = PyModule_GetDict(module_Key);
	PyObject *NameDict = PyModule_GetDict(module_Name);

	// These are used to instantiate new objects in C code
	/* for some reason, this returns NULL
		g_type_CCN = PyDict_GetItemString(CCNDict, "CCN");
	 */
	g_type_CCN = module_CCN;
	assert(g_type_CCN);

	g_type_Interest = PyDict_GetItemString(InterestDict, "Interest");
	assert(g_type_Interest);
	g_type_ContentObject = PyDict_GetItemString(ContentObjectDict, "ContentObject");
	assert(g_type_ContentObject);
	g_type_Closure = PyDict_GetItemString(ClosureDict, "Closure");
	assert(g_type_Closure);
	g_type_Key = PyDict_GetItemString(KeyDict, "Key");
	assert(g_type_Key);
	g_type_Name = PyDict_GetItemString(NameDict, "Name");
	assert(g_type_Name);

	// Additional
	g_type_KeyLocator = PyDict_GetItemString(KeyDict, "KeyLocator");
	assert(g_type_KeyLocator);
	g_type_ExclusionFilter = PyDict_GetItemString(InterestDict, "ExclusionFilter");
	assert(g_type_ExclusionFilter);
	g_type_Signature = PyDict_GetItemString(ContentObjectDict, "Signature");
	assert(g_type_Signature);
	g_type_SignedInfo = PyDict_GetItemString(ContentObjectDict, "SignedInfo");
	assert(g_type_SignedInfo);
	g_type_SigningParams = PyDict_GetItemString(ContentObjectDict, "SigningParams");
	assert(g_type_SigningParams);
	g_type_UpcallInfo = PyDict_GetItemString(ClosureDict, "UpcallInfo");
	assert(g_type_UpcallInfo);

	return;

unload_name:
	Py_DECREF(module_Name);
unload_key:
	Py_DECREF(module_Key);
unload_closure:
	Py_DECREF(module_Closure);
unload_contentobject:
	Py_DECREF(module_ContentObject);
unload_ccn:
	Py_DECREF(module_CCN);
}
