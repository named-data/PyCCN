/*
 * File:   methods_key.h
 * Author: takeda
 *
 * Created on August 14, 2011, 8:14 PM
 */

#ifndef METHODS_KEY_H
#  define	METHODS_KEY_H

struct ccn_pkey *Key_to_ccn_private(PyObject *py_key);
PyObject *Key_from_ccn(struct ccn_pkey *key_ccn);
PyObject *KeyLocator_from_ccn(PyObject *py_keylocator);

PyObject *_pyccn_Key_to_ccn_public(PyObject *self, PyObject *py_key);
PyObject *_pyccn_Key_to_ccn_private(PyObject *self, PyObject *py_key);
PyObject *_pyccn_Key_from_ccn(PyObject *self, PyObject *cobj_key);
PyObject *_pyccn_KeyLocator_to_ccn(PyObject *self, PyObject *args,
		PyObject *kwds);
PyObject *_pyccn_KeyLocator_from_ccn(PyObject *self,
		PyObject *py_keylocator);

#endif	/* METHODS_KEY_H */

