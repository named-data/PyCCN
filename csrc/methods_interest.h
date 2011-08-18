/*
 * File:   methods_interests.h
 * Author: takeda
 *
 * Created on August 15, 2011, 8:59 PM
 */

#ifndef METHODS_INTERESTS_H
#  define	METHODS_INTERESTS_H

PyObject *obj_Interest_from_ccn(PyObject *py_interest);

PyObject *_pyccn_Interest_to_ccn(PyObject *UNUSED(self),
		PyObject *py_interest);
PyObject *_pyccn_Interest_from_ccn(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_ExclusionFilter_to_ccn(PyObject *UNUSED(self),
		PyObject* args);
PyObject *_pyccn_ExclusionFilter_from_ccn(PyObject *UNUSED(self),
		PyObject* args);

#endif	/* METHODS_INTERESTS_H */

