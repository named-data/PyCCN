/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#ifndef METHODS_KEY_H
#  define	METHODS_KEY_H

struct ccn_pkey *Key_to_ccn_private(PyObject *py_key);
PyObject *Key_obj_from_ccn(PyObject *py_key_ccn);
PyObject *KeyLocator_obj_from_ccn(PyObject *py_keylocator);

PyObject *_pyccn_Key_to_ccn_public(PyObject *self, PyObject *py_key);
PyObject *_pyccn_Key_to_ccn_private(PyObject *self, PyObject *py_key);
PyObject *_pyccn_Key_from_ccn(PyObject *self, PyObject *cobj_key);
PyObject *_pyccn_KeyLocator_to_ccn(PyObject *self, PyObject *args,
		PyObject *kwds);
PyObject *_pyccn_KeyLocator_from_ccn(PyObject *self,
		PyObject *py_keylocator);
PyObject *_pyccn_PEM_read_key(PyObject *self, PyObject *args,
		PyObject *py_kwrds);
PyObject *_pyccn_PEM_write_key(PyObject *self, PyObject *args,
		PyObject *py_kwrds);
PyObject *_pyccn_DER_read_key(PyObject *UNUSED(self), PyObject *args,
		PyObject *py_kwds);
PyObject *_pyccn_DER_write_key(PyObject *UNUSED(self), PyObject *args,
		PyObject *py_kwds);

#endif	/* METHODS_KEY_H */

