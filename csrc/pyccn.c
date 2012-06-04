/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#include "python_hdr.h"

#include <ccn/ccn.h>
#include <ccn/hashtb.h>
#include <ccn/uri.h>
#include <ccn/signing.h>

#include "pyccn.h"
#include "key_utils.h"
#include "methods.h"
#include "methods_contentobject.h"
#include "methods_handle.h"
#include "methods_interest.h"
#include "methods_key.h"
#include "methods_name.h"
#include "methods_signature.h"
#include "methods_signedinfo.h"
#include "util.h"

#if PY_MAJOR_VERSION >= 3
#    define INITERROR return NULL
#    define MODINIT(name) \
            PyMODINIT_FUNC \
            PyInit_ ## name(void)
#else
struct pyccn_state _pyccn_state;
#    define INITERROR return
#    define MODINIT(name) \
            PyMODINIT_FUNC \
            init ## name(void)
#endif

MODINIT(_pyccn);

PyObject *_pyccn_module;

// Exceptions
PyObject *g_PyExc_CCNError;
PyObject *g_PyExc_CCNNameError;
PyObject *g_PyExc_CCNKeyLocatorError;
PyObject *g_PyExc_CCNSignatureError;
PyObject *g_PyExc_CCNSignedInfoError;
PyObject *g_PyExc_CCNInterestError;
PyObject *g_PyExc_CCNExclusionFilterError;
PyObject *g_PyExc_CCNKeyError;
PyObject *g_PyExc_CCNContentObjectError;

static PyMethodDef g_module_methods[] = {
	{"create", _pyccn_cmd_create, METH_NOARGS, NULL},
	{"connect", _pyccn_cmd_connect, METH_O, NULL},
	{"disconnect", _pyccn_cmd_disconnect, METH_O, NULL},
	{"get_connection_fd", _pyccn_get_connection_fd, METH_O, NULL},
	{"process_scheduled_operations", _pyccn_cmd_process_scheduled_operations,
		METH_O, NULL},
	{"output_is_pending", _pyccn_cmd_output_is_pending, METH_O, NULL},
	{"run", _pyccn_cmd_run, METH_VARARGS, NULL},
	{"set_run_timeout", _pyccn_cmd_set_run_timeout, METH_VARARGS, NULL},
	{"is_run_executing", _pyccn_cmd_is_run_executing, METH_O, NULL},
	{"express_interest", _pyccn_cmd_express_interest, METH_VARARGS, NULL},
	{"set_interest_filter", _pyccn_cmd_set_interest_filter, METH_VARARGS, NULL},
	{"get", _pyccn_cmd_get, METH_VARARGS, NULL},
	{"put", _pyccn_cmd_put, METH_VARARGS, NULL},
	{"get_default_key", _pyccn_cmd_get_default_key, METH_NOARGS, NULL},
	{"generate_RSA_key", _pyccn_cmd_generate_RSA_key, METH_VARARGS, NULL},
	{"PEM_read_key", (PyCFunction) _pyccn_cmd_PEM_read_key,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"PEM_write_key", (PyCFunction) _pyccn_cmd_PEM_write_key,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"DER_read_key", (PyCFunction) _pyccn_cmd_DER_read_key,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"DER_write_key", (PyCFunction) _pyccn_cmd_DER_write_key,
		METH_VARARGS | METH_KEYWORDS, NULL},

	// ** Methods of ContentObject
	//
	{"content_to_bytearray", _pyccn_cmd_content_to_bytearray, METH_O, NULL},
	{"content_to_bytes", _pyccn_cmd_content_to_bytes, METH_O, NULL},
	{"verify_content", _pyccn_cmd_verify_content, METH_VARARGS, NULL},
	{"verify_signature", _pyccn_cmd_verify_signature, METH_VARARGS, NULL},
#if 0
	{"_pyccn_ccn_chk_signing_params", _pyccn_ccn_chk_signing_params, METH_VARARGS,
		""},
	{"_pyccn_ccn_signed_info_create", _pyccn_ccn_signed_info_create, METH_VARARGS,
		""},
#endif

	// Naming
	{"name_from_uri", _pyccn_cmd_name_from_uri, METH_O, NULL},
	{"name_to_uri", _pyccn_cmd_name_to_uri, METH_O, NULL},
	{"compare_names", _pyccn_cmd_compare_names, METH_VARARGS, NULL},

#if 0
	{"_pyccn_ccn_name_append_nonce", _pyccn_ccn_name_append_nonce, METH_VARARGS,
		""},
#endif

	// Converters
	{"name_comps_to_ccn", _pyccn_cmd_name_comps_to_ccn, METH_O, NULL},
	{"name_comps_from_ccn", _pyccn_cmd_name_comps_from_ccn, METH_O, NULL},
	{"Interest_obj_to_ccn", _pyccn_cmd_Interest_obj_to_ccn, METH_O, NULL},
	{"Interest_obj_from_ccn", _pyccn_cmd_Interest_obj_from_ccn, METH_O, NULL},
	{"encode_ContentObject", _pyccn_cmd_encode_ContentObject, METH_VARARGS,
		NULL},
	{"ContentObject_obj_from_ccn", _pyccn_cmd_ContentObject_obj_from_ccn,
		METH_O, NULL},
	{"digest_contentobject", _pyccn_cmd_digest_contentobject, METH_VARARGS,
		NULL},
	{"content_matches_interest", _pyccn_cmd_content_matches_interest,
		METH_VARARGS, NULL},
	{"Key_obj_from_ccn", _pyccn_cmd_Key_obj_from_ccn, METH_O, NULL},
	{"KeyLocator_to_ccn", (PyCFunction) _pyccn_cmd_KeyLocator_to_ccn,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"KeyLocator_obj_from_ccn", _pyccn_cmd_KeyLocator_obj_from_ccn, METH_O,
		NULL},
	{"Signature_obj_to_ccn", _pyccn_cmd_Signature_obj_to_ccn, METH_O, NULL},
	{"Signature_obj_from_ccn", _pyccn_cmd_Signature_obj_from_ccn, METH_O, NULL},
	{"SignedInfo_to_ccn", (PyCFunction) _pyccn_cmd_SignedInfo_to_ccn,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"SignedInfo_obj_from_ccn", _pyccn_cmd_SignedInfo_obj_from_ccn, METH_O,
		NULL},
#if 0
	{"_pyccn_SigningParams_to_ccn", _pyccn_SigningParams_to_ccn, METH_VARARGS,
		""},
	{"_pyccn_SigningParams_from_ccn", _pyccn_SigningParams_from_ccn, METH_O, NULL},
#endif
	{"ExclusionFilter_names_to_ccn", _pyccn_cmd_ExclusionFilter_names_to_ccn,
		METH_O, NULL},
	{"ExclusionFilter_obj_from_ccn", _pyccn_cmd_ExclusionFilter_obj_from_ccn,
		METH_O, NULL},
	{"dump_charbuf", _pyccn_cmd_dump_charbuf, METH_O, NULL},
	{"new_charbuf", _pyccn_cmd_new_charbuf, METH_VARARGS, NULL},

	{NULL, NULL, 0, NULL} /* Sentinel */
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef g_moduledef = {
	PyModuleDef_HEAD_INIT,
	"pyccn._pyccn",
	NULL,
	sizeof(struct pyccn_state),
	g_module_methods,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif

#define NEW_EXCEPTION(NAME, DESC, BASE) \
do { \
	g_PyExc_ ## NAME = \
		PyErr_NewExceptionWithDoc("_pyccn." #NAME, DESC, BASE, NULL); \
	Py_INCREF(g_PyExc_ ## NAME); /* PyModule_AddObject steals reference */ \
	PyModule_AddObject(_pyccn_module, #NAME, g_PyExc_ ## NAME); \
} while(0)

static int
initialize_exceptions(void)
{
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
	NEW_EXCEPTION(CCNContentObjectError, "CCN ContentObject Error",
			g_PyExc_CCNError);

	return 0;
}

PyObject *
_pyccn_get_type(enum e_class_type type)
{
	PyObject *py_module, *py_dict, *py_type;
	struct pyccn_state *state;

	static struct modules {
		enum e_class_type type;
		const char *module;
		const char *class;
	} modules[] = {
		{CCN, "pyccn.CCN", "CCN"},
		{Closure, "pyccn.Closure", "Closure"},
		{ContentObject, "pyccn.ContentObject", "ContentObject"},
		{ExclusionFilter, "pyccn.Interest", "ExclusionFilter"},
		{Interest, "pyccn.Interest", "Interest"},
		{Key, "pyccn.Key", "Key"},
		{KeyLocator, "pyccn.Key", "KeyLocator"},
		{Name, "pyccn.Name", "Name"},
		{Signature, "pyccn.ContentObject", "Signature"},
		{SignedInfo, "pyccn.ContentObject", "SignedInfo"},
		{SigningParams, "pyccn.ContentObject", "SigningParams"},
		{UpcallInfo, "pyccn.Closure", "UpcallInfo"},
		{CLASS_TYPE_COUNT, NULL, NULL}
	};
	struct modules *p;

	assert(_pyccn_module);

	state = GETSTATE(_pyccn_module);
	assert(state);

	p = &modules[type];
	assert(p->type == type);

	if (state->class_type[type])
		return state->class_type[type];

	py_module = PyImport_ImportModule(p->module);
	if (!py_module)
		return NULL;

	py_dict = PyModule_GetDict(py_module);
	assert(py_dict);

	py_type = PyDict_GetItemString(py_dict, p->class);
	if (!py_type) {
		PyErr_Format(PyExc_SystemError, "Error obtaining type for %s [%d]",
				p->class, type);
		return NULL;
	}

	Py_INCREF(py_type);
	state->class_type[type] = py_type;

	debug("Successfully obtained type for %s [%d]\n", p->class, type);
	return py_type;
}

MODINIT(_pyccn)
{
#if PY_MAJOR_VERSION >= 3
	_pyccn_module = PyModule_Create(&g_moduledef);
#else
	_pyccn_module = Py_InitModule("pyccn._pyccn", g_module_methods);
#endif
	if (!_pyccn_module) {
		fprintf(stderr, "Unable to initialize PyCCN module\n");
		INITERROR;
	}

	initialize_exceptions();

	initialize_crypto();

#if PY_MAJOR_VERSION >= 3
	return _pyccn_module;
#else
	return;
#endif
}
