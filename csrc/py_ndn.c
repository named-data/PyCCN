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

#include "py_ndn.h"
#include "util.h"
#include "key_utils.h"
#include "methods.h"
#include "methods_contentobject.h"
#include "methods_handle.h"
#include "methods_interest.h"
#include "methods_key.h"
#include "methods_name.h"
#include "methods_signature.h"
#include "methods_signedinfo.h"

#ifdef NAMECRYPTO
#    include "methods_namecrypto.h"
#endif

#if PY_MAJOR_VERSION >= 3
#    define INITERROR return NULL
#    define MODINIT(name) \
            PyMODINIT_FUNC \
            PyInit_ ## name(void)
#else
struct py_ndn_state _ndn_state;
#    define INITERROR return
#    define MODINIT(name) \
            PyMODINIT_FUNC \
            init ## name(void)
#endif

MODINIT(_ndn);

PyObject *_ndn_module;

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
	{"create", _ndn_cmd_create, METH_NOARGS, NULL},
	{"connect", _ndn_cmd_connect, METH_O, NULL},
	{"disconnect", _ndn_cmd_disconnect, METH_O, NULL},
	{"defer_verification", _ndn_cmd_defer_verification, METH_VARARGS, NULL},
	{"get_connection_fd", _ndn_get_connection_fd, METH_O, NULL},
	{"process_scheduled_operations", _ndn_cmd_process_scheduled_operations,
		METH_O, NULL},
	{"output_is_pending", _ndn_cmd_output_is_pending, METH_O, NULL},
	{"run", _ndn_cmd_run, METH_VARARGS, NULL},
	{"set_run_timeout", _ndn_cmd_set_run_timeout, METH_VARARGS, NULL},
	{"is_run_executing", _ndn_cmd_is_run_executing, METH_O, NULL},
	{"express_interest", _ndn_cmd_express_interest, METH_VARARGS, NULL},
	{"set_interest_filter", _ndn_cmd_set_interest_filter, METH_VARARGS, NULL},
	{"clear_interest_filter", _ndn_cmd_clear_interest_filter, METH_VARARGS, NULL},
	{"get", _ndn_cmd_get, METH_VARARGS, NULL},
	{"put", _ndn_cmd_put, METH_VARARGS, NULL},
	{"get_default_key", _ndn_cmd_get_default_key, METH_NOARGS, NULL},
        {"get_default_key_name", _ndn_cmd_get_default_key_name, METH_NOARGS, NULL},
	{"generate_RSA_key", _ndn_cmd_generate_RSA_key, METH_VARARGS, NULL},
	{"PEM_read_key", (PyCFunction) _ndn_cmd_PEM_read_key,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"PEM_write_key", (PyCFunction) _ndn_cmd_PEM_write_key,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"DER_read_key", (PyCFunction) _ndn_cmd_DER_read_key,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"DER_write_key", (PyCFunction) _ndn_cmd_DER_write_key,
		METH_VARARGS | METH_KEYWORDS, NULL},

	// ** Methods of ContentObject
	//
	{"content_to_bytearray", _ndn_cmd_content_to_bytearray, METH_O, NULL},
	{"content_to_bytes", _ndn_cmd_content_to_bytes, METH_O, NULL},
	{"verify_content", _ndn_cmd_verify_content, METH_VARARGS, NULL},
	{"verify_signature", _ndn_cmd_verify_signature, METH_VARARGS, NULL},
#if 0
	{"_ndn_ccn_chk_signing_params", _ndn_ccn_chk_signing_params, METH_VARARGS,
		""},
	{"_ndn_ccn_signed_info_create", _ndn_ccn_signed_info_create, METH_VARARGS,
		""},
#endif

	// Naming
	{"name_from_uri", _ndn_cmd_name_from_uri, METH_O, NULL},
	{"name_to_uri", _ndn_cmd_name_to_uri, METH_O, NULL},
	{"compare_names", _ndn_cmd_compare_names, METH_VARARGS, NULL},

#if 0
	{"_ndn_ccn_name_append_nonce", _ndn_ccn_name_append_nonce, METH_VARARGS,
		""},
#endif

	// Converters
	{"name_comps_to_ccn", _ndn_cmd_name_comps_to_ccn, METH_O, NULL},
        
        {"name_comps_from_ccn_buffer", _ndn_cmd_name_comps_from_ccn_buffer, METH_O, NULL},
	{"name_comps_from_ccn", _ndn_cmd_name_comps_from_ccn, METH_O, NULL},
	{"Interest_obj_to_ccn", _ndn_cmd_Interest_obj_to_ccn, METH_O, NULL},
	{"Interest_obj_from_ccn", _ndn_cmd_Interest_obj_from_ccn, METH_O, NULL},
	{"encode_ContentObject", _ndn_cmd_encode_ContentObject, METH_VARARGS,
		NULL},
	{"ContentObject_obj_from_ccn", _ndn_cmd_ContentObject_obj_from_ccn,
		METH_O, NULL},
        {"ContentObject_obj_from_ccn_buffer", _ndn_cmd_ContentObject_obj_from_ccn_buffer, METH_O, NULL},
	{"digest_contentobject", _ndn_cmd_digest_contentobject, METH_VARARGS,
		NULL},
	{"content_matches_interest", _ndn_cmd_content_matches_interest,
		METH_VARARGS, NULL},
	{"Key_obj_from_ccn", _ndn_cmd_Key_obj_from_ccn, METH_O, NULL},
	{"KeyLocator_to_ccn", (PyCFunction) _ndn_cmd_KeyLocator_to_ccn,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"KeyLocator_obj_from_ccn", _ndn_cmd_KeyLocator_obj_from_ccn, METH_O,
		NULL},
	{"Signature_obj_to_ccn", _ndn_cmd_Signature_obj_to_ccn, METH_O, NULL},
	{"Signature_obj_from_ccn", _ndn_cmd_Signature_obj_from_ccn, METH_O, NULL},
	{"SignedInfo_to_ccn", (PyCFunction) _ndn_cmd_SignedInfo_to_ccn,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"SignedInfo_obj_from_ccn", _ndn_cmd_SignedInfo_obj_from_ccn, METH_O,
		NULL},
#if 0
	{"_ndn_SigningParams_to_ccn", _ndn_SigningParams_to_ccn, METH_VARARGS,
		""},
	{"_ndn_SigningParams_from_ccn", _ndn_SigningParams_from_ccn, METH_O, NULL},
#endif
	{"ExclusionFilter_names_to_ccn", _ndn_cmd_ExclusionFilter_names_to_ccn,
		METH_O, NULL},
	{"ExclusionFilter_obj_from_ccn", _ndn_cmd_ExclusionFilter_obj_from_ccn,
		METH_O, NULL},
	{"dump_charbuf", _ndn_cmd_dump_charbuf, METH_O, NULL},
	{"new_charbuf", _ndn_cmd_new_charbuf, METH_VARARGS, NULL},

#ifdef NAMECRYPTO
	{"nc_new_state", _ndn_cmd_nc_new_state, METH_NOARGS, NULL},
	{"nc_authenticate_command", _ndn_cmd_nc_authenticate_command, METH_VARARGS,
		NULL},
	{"nc_authenticate_command_sig", _ndn_cmd_nc_authenticate_command_sig,
		METH_VARARGS, NULL},
	{"nc_verify_command", (PyCFunction) _ndn_cmd_nc_verify_command,
		METH_VARARGS | METH_KEYWORDS, NULL},
	{"nc_app_id", _ndn_cmd_nc_app_id, METH_O, NULL},
	{"nc_app_key", _ndn_cmd_nc_app_key, METH_VARARGS, NULL},
#endif
	{NULL, NULL, 0, NULL} /* Sentinel */
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef g_moduledef = {
	PyModuleDef_HEAD_INIT,
	"ndn._ndn",
	NULL,
	sizeof(struct py_ndn_state),
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
		PyErr_NewExceptionWithDoc("_ndn." #NAME, DESC, BASE, NULL); \
	Py_INCREF(g_PyExc_ ## NAME); /* PyModule_AddObject steals reference */ \
	PyModule_AddObject(_ndn_module, #NAME, g_PyExc_ ## NAME); \
} while(0)

static int
initialize_exceptions(void)
{
	NEW_EXCEPTION(CCNError, "General NDN Exception", NULL);
	NEW_EXCEPTION(CCNNameError, "NDN Name Exception", g_PyExc_CCNError);
	NEW_EXCEPTION(CCNKeyLocatorError, "NDN KeyLocator Exception",
			g_PyExc_CCNError);
	NEW_EXCEPTION(CCNSignatureError, "NDN Signature Exception",
			g_PyExc_CCNError);
	NEW_EXCEPTION(CCNSignedInfoError, "NDN SignedInfo Exception",
			g_PyExc_CCNError);
	NEW_EXCEPTION(CCNInterestError, "NDN Interest Exception",
			g_PyExc_CCNError);
	NEW_EXCEPTION(CCNExclusionFilterError, "NDN ExclusionFilter Exception",
			g_PyExc_CCNInterestError);
	NEW_EXCEPTION(CCNKeyError, "NDN Key Exception", g_PyExc_CCNKeyError);
	NEW_EXCEPTION(CCNContentObjectError, "NDN ContentObject Error",
			g_PyExc_CCNError);

	return 0;
}

PyObject *
_ndn_get_type(enum e_class_type type)
{
	PyObject *py_module, *py_dict, *py_type;
	struct py_ndn_state *state;

	static struct modules {
		enum e_class_type type;
		const char *module;
		const char *class;
	} modules[] = {
		{Face, "ndn.Face", "Face"},
		{Closure, "ndn.Closure", "Closure"},
		{ContentObject, "ndn.ContentObject", "ContentObject"},
		{ExclusionFilter, "ndn.Interest", "ExclusionFilter"},
		{Interest, "ndn.Interest", "Interest"},
		{Key, "ndn.Key", "Key"},
		{KeyLocator, "ndn.Key", "KeyLocator"},
		{Name, "ndn.Name", "Name"},
		{Signature, "ndn.ContentObject", "Signature"},
		{SignedInfo, "ndn.ContentObject", "SignedInfo"},
		{SigningParams, "ndn.ContentObject", "SigningParams"},
		{UpcallInfo, "ndn.Closure", "UpcallInfo"},
		{CLASS_TYPE_COUNT, NULL, NULL}
	};
	struct modules *p;

	assert(_ndn_module);

	state = GETSTATE(_ndn_module);
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

MODINIT(_ndn)
{
#if PY_MAJOR_VERSION >= 3
	_ndn_module = PyModule_Create(&g_moduledef);
#else
	_ndn_module = Py_InitModule("ndn._ndn", g_module_methods);
#endif
	if (!_ndn_module) {
		fprintf(stderr, "Unable to initialize py-ndn module\n");
		INITERROR;
	}

	initialize_exceptions();

	initialize_crypto();

#if PY_MAJOR_VERSION >= 3
	return _ndn_module;
#else
	return;
#endif
}
