/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#ifndef METHODS_SIGNATURE_H
#  define	METHODS_SIGNATURE_H

PyObject *Signature_obj_from_ccn(PyObject *py_signature);
PyObject *_pyccn_cmd_Signature_obj_to_ccn(PyObject* self, PyObject* args);
PyObject *_pyccn_cmd_Signature_obj_from_ccn(PyObject* self, PyObject* args);

#endif	/* METHODS_SIGNATURE_H */
