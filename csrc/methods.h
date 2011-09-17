/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#ifndef METHODS_H
#  define	METHODS_H

PyObject *_pyccn_ccn_create(PyObject *UNUSED(self), PyObject *UNUSED(args));
PyObject *_pyccn_ccn_connect(PyObject *UNUSED(self), PyObject *py_ccn_handle);
PyObject *_pyccn_ccn_disconnect(PyObject *UNUSED(self),
		PyObject *py_ccn_handle);
PyObject *_pyccn_get_connection_fd(PyObject *self, PyObject *py_handle);
PyObject *_pyccn_process_scheduled_operations(PyObject *self,
		PyObject *py_handle);
PyObject *_pyccn_output_is_pending(PyObject *self, PyObject *py_handle);
PyObject *_pyccn_ccn_run(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_ccn_set_run_timeout(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_is_upcall_executing(PyObject *self, PyObject *py_handle);
PyObject *_pyccn_ccn_express_interest(PyObject *UNUSED(self),
		PyObject *args);
PyObject *_pyccn_ccn_set_interest_filter(PyObject *UNUSED(self),
		PyObject *args);
PyObject *_pyccn_ccn_get(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_ccn_put(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_ccn_get_default_key(PyObject *self, PyObject *arg);
PyObject *_pyccn_generate_RSA_key(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_SigningParams_from_ccn(PyObject *UNUSED(self),
		PyObject *py_signing_params);
PyObject *_pyccn_UpcallInfo_from_ccn(PyObject *UNUSED(self),
		PyObject *py_upcall_info);
PyObject *_pyccn_dump_charbuf(PyObject *self, PyObject *py_charbuf);

#endif	/* METHODS_H */

