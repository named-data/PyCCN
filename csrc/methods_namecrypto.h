/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 * Updated by: Wentao Shang <wentao@cs.ucla.edu>
 */

#ifndef METHODS_NAMECRYPTO_H
#  define	METHODS_NAMECRYPTO_H

PyObject *_pyccn_cmd_nc_new_state(PyObject *self, PyObject *args);
PyObject *_pyccn_cmd_nc_authenticate_command(PyObject *self, PyObject *args);
PyObject *_pyccn_cmd_nc_authenticate_command_sig(PyObject *self,
		PyObject *args);
PyObject *_pyccn_cmd_nc_verify_command(PyObject *self, PyObject *args,
		PyObject *kwds);
PyObject *_pyccn_cmd_nc_app_id(PyObject *self, PyObject *py_appname);
PyObject *_pyccn_cmd_nc_app_key(PyObject *self, PyObject *args);

#endif	/* METHODS_NAMECRYPTO_H */

