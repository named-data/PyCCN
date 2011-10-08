/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#ifndef METHODS_H
#  define	METHODS_H

PyObject *_pyccn_cmd_generate_RSA_key(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_SigningParams_from_ccn(PyObject *UNUSED(self),
		PyObject *py_signing_params);
PyObject *_pyccn_cmd_dump_charbuf(PyObject *self, PyObject *py_charbuf);
PyObject *_pyccn_cmd_new_charbuf(PyObject *self, PyObject *args);

#endif	/* METHODS_H */
