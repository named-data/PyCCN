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

PyObject *_ndn_cmd_Key_obj_from_ccn(PyObject *self, PyObject *cobj_key);
PyObject *_ndn_cmd_KeyLocator_to_ccn(PyObject *self, PyObject *args,
		PyObject *kwds);
PyObject *_ndn_cmd_KeyLocator_obj_from_ccn(PyObject *self,
		PyObject *py_keylocator);
PyObject *_ndn_cmd_PEM_read_key(PyObject *self, PyObject *args,
		PyObject *py_kwrds);
PyObject *_ndn_cmd_PEM_write_key(PyObject *self, PyObject *args,
		PyObject *py_kwrds);
PyObject *_ndn_cmd_DER_read_key(PyObject *UNUSED(self), PyObject *args,
		PyObject *py_kwds);
PyObject *_ndn_cmd_DER_write_key(PyObject *UNUSED(self), PyObject *args,
		PyObject *py_kwds);

#endif	/* METHODS_KEY_H */

