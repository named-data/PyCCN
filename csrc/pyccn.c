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
#include <ccn/hashtb.h>
#include <ccn/uri.h>
#include <ccn/signing.h>

#include "pyccn.h"
#include "key_utils.h"
#include "methods.h"
#include "util.h"

PyThreadState *_pyccn_thread_state = NULL;

// Primary types for the Python libraries,
// taken directly from the CCNx wire format
PyObject *g_type_Name;
PyObject *g_type_CCN;
PyObject *g_type_Interest;
PyObject *g_type_ContentObject;
PyObject *g_type_Closure;
PyObject *g_type_Key;

// Plus some secondary helper types, which
// are declared as inner classes.
PyObject *g_type_ExclusionFilter;
PyObject *g_type_KeyLocator;
PyObject *g_type_Signature;
PyObject *g_type_SignedInfo;
PyObject *g_type_SigningParams;
PyObject *g_type_UpcallInfo;

// Exceptions
PyObject *g_PyExc_CCNError;
PyObject *g_PyExc_CCNNameError;
PyObject *g_PyExc_CCNKeyLocatorError;
PyObject *g_PyExc_CCNSignatureError;
PyObject *g_PyExc_CCNSignedInfoError;
PyObject *g_PyExc_CCNInterestError;
PyObject *g_PyExc_CCNExclusionFilterError;
PyObject *g_PyExc_CCNKeyError;

static PyObject *
import_module(PyObject **module, const char *name)
{
	assert(module);
	assert(name);

	*module = PyImport_ImportModule(name);
	if (*module)
		return *module;

	fprintf(stderr, "Unable to import %s\n", name);

	return NULL;
}

#define NEW_EXCEPTION(NAME, DESC, BASE) \
do { \
	g_PyExc_ ## NAME = \
		PyErr_NewExceptionWithDoc("_pyccn." #NAME, DESC, BASE, NULL); \
	Py_INCREF(g_PyExc_ ## NAME); /* PyModule_AddObject steals reference */ \
	PyModule_AddObject(module, #NAME, g_PyExc_ ## NAME); \
} while(0)

PyMODINIT_FUNC
init_pyccn(void)
{
	PyObject *module;
	PyObject *py_module_Name, *py_module_CCN, *py_module_Interest;
	PyObject *py_module_ContentObject, *py_module_Closure, *py_module_Key;

	module = initialize_methods("pyccn._pyccn");
	if (!module) {
		fprintf(stderr, "Unable to initialize PyCCN module\n");
		return;
	}

	NEW_EXCEPTION(CCNError, "General CCN Exception", NULL);
	NEW_EXCEPTION(CCNNameError, "CCN Name Exception", g_PyExc_CCNError);
	NEW_EXCEPTION(CCNKeyLocatorError, "CCN KeyLocator Exception",
			g_PyExc_CCNError);
	NEW_EXCEPTION(CCNSignatureError, "CCN Signature Exception",
			g_PyExc_CCNError);
	NEW_EXCEPTION(CCNSignedInfoError, "CCN SignedInfo Exception",
			g_PyExc_CCNError);
	NEW_EXCEPTION(CCNInterestError, "CCN Interest Exception",
			g_PyExc_CCNError);
	NEW_EXCEPTION(CCNExclusionFilterError, "CCN ExclusionFilter Exception",
			g_PyExc_CCNInterestError);
	NEW_EXCEPTION(CCNKeyError, "CCN Key Exception", g_PyExc_CCNKeyError);

	if (!import_module(&py_module_CCN, "pyccn.CCN"))
		return; //XXX: How to uninitialize methods?

	if (!import_module(&py_module_Interest, "pyccn.Interest"))
		goto unload_ccn;

	if (!import_module(&py_module_ContentObject, "pyccn.ContentObject"))
		goto unload_interest;

	if (!import_module(&py_module_Closure, "pyccn.Closure"))
		goto unload_contentobject;

	if (!import_module(&py_module_Key, "pyccn.Key"))
		goto unload_closure;

	if (!import_module(&py_module_Name, "pyccn.Name"))
		goto unload_key;

	PyObject *py_dict_CCN, *py_dict_Interest, *py_dict_ContentObject;
	PyObject *py_dict_Closure, *py_dict_Key, *py_dict_Name;

	py_dict_CCN = PyModule_GetDict(py_module_CCN);
	py_dict_Interest = PyModule_GetDict(py_module_Interest);
	py_dict_ContentObject = PyModule_GetDict(py_module_ContentObject);
	py_dict_Closure = PyModule_GetDict(py_module_Closure);
	py_dict_Key = PyModule_GetDict(py_module_Key);
	py_dict_Name = PyModule_GetDict(py_module_Name);

	// These are used to instantiate new objects in C code
	g_type_CCN = PyDict_GetItemString(py_dict_CCN, "CCN");
	assert(g_type_CCN);
	g_type_Interest = PyDict_GetItemString(py_dict_Interest, "Interest");
	assert(g_type_Interest);
	g_type_ContentObject = PyDict_GetItemString(py_dict_ContentObject,
			"ContentObject");
	assert(g_type_ContentObject);
	g_type_Closure = PyDict_GetItemString(py_dict_Closure, "Closure");
	assert(g_type_Closure);
	g_type_Key = PyDict_GetItemString(py_dict_Key, "Key");
	assert(g_type_Key);
	g_type_Name = PyDict_GetItemString(py_dict_Name, "Name");
	assert(g_type_Name);

	// Additional
	g_type_KeyLocator = PyDict_GetItemString(py_dict_Key, "KeyLocator");
	assert(g_type_KeyLocator);
	g_type_ExclusionFilter = PyDict_GetItemString(py_dict_Interest,
			"ExclusionFilter");
	assert(g_type_ExclusionFilter);
	g_type_Signature = PyDict_GetItemString(py_dict_ContentObject, "Signature");
	assert(g_type_Signature);
	g_type_SignedInfo = PyDict_GetItemString(py_dict_ContentObject,
			"SignedInfo");
	assert(g_type_SignedInfo);
	g_type_SigningParams = PyDict_GetItemString(py_dict_ContentObject,
			"SigningParams");
	assert(g_type_SigningParams);
	g_type_UpcallInfo = PyDict_GetItemString(py_dict_Closure, "UpcallInfo");
	assert(g_type_UpcallInfo);

	return;

unload_key:
	Py_DECREF(py_module_Key);
unload_closure:
	Py_DECREF(py_module_Closure);
unload_contentobject:
	Py_DECREF(py_module_ContentObject);
unload_interest:
	Py_DECREF(py_module_Interest);
unload_ccn:
	Py_DECREF(py_module_CCN);
}
