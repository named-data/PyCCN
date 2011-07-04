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
PyObject* g_type_Name;
static PyObject* g_type_CCN;
PyObject* g_type_Interest;
PyObject* g_type_ContentObject;
static PyObject* g_type_Closure;
PyObject* g_type_Key;

// Plus some secondary helper types, which
// are declared as inner classes.
//
PyObject* g_type_ExclusionFilter;
PyObject* g_type_KeyLocator;
PyObject* g_type_Signature;
PyObject* g_type_SignedInfo;
PyObject* g_type_SigningParams;
PyObject* g_type_UpcallInfo;

// Pointers to the various modules themselves.
//
static PyObject* g_module_Name;
static PyObject* g_module_CCN;
static PyObject* g_module_Interest;
PyObject* g_module_ContentObject;
static PyObject* g_module_Closure;
static PyObject* g_module_Key;


// Called by destructor
//

void
__ccn_destroy(void* p)
{
	if (p != NULL) {
		ccn_disconnect((struct ccn*) p); // Ok to call this even if already disconn?
		ccn_destroy((struct ccn**) &p);
	}
}

//
// WRAPPERS FOR VARIOUS CCNx LIBRARY FUNCTIONS
// SOME OF WHICH BECOME OBJECT METHODS IN THE
// PYTHON LIBRARY - SEE THE PYTHON CODE FOR
// CLARIFICATION.
//
//

enum ccn_upcall_res
__ccn_upcall_handler(struct ccn_closure *selfp,
    enum ccn_upcall_kind upcall_kind,
    struct ccn_upcall_info *info)
{

	PyObject* py_closure = (PyObject*) selfp->data;
	PyObject* upcall_method = PyObject_GetAttrString(py_closure, "upcall");
	PyObject* py_upcall_info = UpcallInfo_from_ccn(info);
	// Refs?


	PyObject* arglist = Py_BuildValue("iO", upcall_kind, py_upcall_info);

	fprintf(stderr, "Calling upcall\n");
	PyObject* result = PyObject_CallObject(upcall_method, arglist);
	Py_DECREF(arglist); // per docs.python.org

	return(enum ccn_upcall_res) PyInt_AsLong(result);
}

void
__ccn_closure_destroy(void *p)
{
	if (p != NULL)
		free(p);
}



static bool
import_module(PyObject **module, char *name)
{
	PyObject *what;

	assert(module);
	assert(name);

	what = PyString_FromString(name);
	*module = PyImport_ImportModuleLevel("pyccn", NULL, NULL, what, 0);
	Py_DECREF(what);
	if (*module)
		return true;

	fprintf(stderr, "Unable to import %s\n", name);

	return false;
}

PyMODINIT_FUNC
init_pyccn(void)
{
	PyObject *module;

	module = initialize_methods("_pyccn");
	if (!module) {
		fprintf(stderr, "Unable to initialize PyCCN module\n");
		return;
	}

	if (!import_module(&g_module_CCN, "CCN"))
		return; //XXX: How to unload a module?

	if (!import_module(&g_module_Interest, "Interest"))
		goto unload_ccn;

	if (!import_module(&g_module_ContentObject, "ContentObject"))
		goto unload_contentobject;

	if (!import_module(&g_module_Closure, "Closure"))
		goto unload_closure;

	if (!import_module(&g_module_Key, "Key"))
		goto unload_key;

	if (!import_module(&g_module_Name, "Name"))
		goto unload_name;

	PyObject* CCNDict = PyModule_GetDict(g_module_CCN);
	PyObject* InterestDict = PyModule_GetDict(g_module_Interest);
	PyObject* ContentObjectDict = PyModule_GetDict(g_module_ContentObject);
	PyObject* ClosureDict = PyModule_GetDict(g_module_Closure);
	PyObject* KeyDict = PyModule_GetDict(g_module_Key);
	PyObject* NameDict = PyModule_GetDict(g_module_Name);

	// These are used to instantiate new objects in C code
	g_type_CCN = PyDict_GetItemString(CCNDict, "CCN");
	g_type_Interest = PyDict_GetItemString(InterestDict, "Interest");
	g_type_ContentObject = PyDict_GetItemString(ContentObjectDict, "ContentObject");
	g_type_Closure = PyDict_GetItemString(ClosureDict, "Closure");
	g_type_Key = PyDict_GetItemString(KeyDict, "Key");
	g_type_Name = PyDict_GetItemString(NameDict, "Name");

	// Additional
	g_type_KeyLocator = PyDict_GetItemString(KeyDict, "KeyLocator");
	g_type_ExclusionFilter = PyDict_GetItemString(InterestDict, "ExclusionFilter");
	g_type_Signature = PyDict_GetItemString(ContentObjectDict, "Signature");
	g_type_SignedInfo = PyDict_GetItemString(ContentObjectDict, "SignedInfo");
	g_type_SigningParams = PyDict_GetItemString(ContentObjectDict, "SigningParams");
	g_type_UpcallInfo = PyDict_GetItemString(ClosureDict, "UpcallInfo");

	return;

unload_name:
	Py_DECREF(g_module_Name);
unload_key:
	Py_DECREF(g_module_Key);
unload_closure:
	Py_DECREF(g_module_Closure);
unload_contentobject:
	Py_DECREF(g_module_ContentObject);
unload_ccn:
	Py_DECREF(g_module_CCN);
}
