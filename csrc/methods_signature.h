/*
 * File:   methods_signature.h
 * Author: takeda
 *
 * Created on August 12, 2011, 11:30 PM
 */

#ifndef METHODS_SIGNATURE_H
#  define	METHODS_SIGNATURE_H

PyObject *Signature_obj_from_ccn(PyObject *py_signature);
PyObject *_pyccn_Signature_to_ccn(PyObject* self, PyObject* args);
PyObject *_pyccn_Signature_from_ccn(PyObject* self, PyObject* args);

#endif	/* METHODS_SIGNATURE_H */
