/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 */

#include "python_hdr.h"

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

MODINIT(_namecrypto);

PyObject *_namecrypto_module;

static PyMethodDef g_module_methods[] = {
	{"create", _pyccn_cmd_create, METH_NOARGS, NULL},
	{NULL, NULL, 0, NULL} /* Sentinel */
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef g_moduledef = {
	PyModuleDef_HEAD_INIT,
	"pyccn._namecrypto",
	NULL,
	0,
	g_module_methods,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif

static PyObject *
_namecrypto_authenticate_command(PyObject *self, PyObject *args)
{
	
}

MODINIT(_namecrypto)
{
#if PY_MAJOR_VERSION >= 3
	_namecrypto_module = PyModule_Create(&g_moduledef);
#else
	_namecrypto_module = Py_InitModule("pyccn._namecrypto", g_module_methods);
#endif
	if (!_namecrypto_module) {
		fprintf(stderr, "Unable to initialize namecrypto module\n");
		INITERROR;
	}

#if PY_MAJOR_VERSION >= 3
	return _namecrypto_module;
#else
	return;
#endif
}
