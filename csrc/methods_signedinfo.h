/*
 * File:   methods_signedinfo.h
 * Author: takeda
 *
 * Created on August 14, 2011, 1:42 AM
 */

#ifndef METHODS_SIGNEDINFO_H
#  define	METHODS_SIGNEDINFO_H

PyObject *SignedInfo_obj_from_ccn(PyObject *py_signed_info);
PyObject *_pyccn_SignedInfo_to_ccn(PyObject *self, PyObject *args,
		PyObject *kwds);
PyObject *_pyccn_SignedInfo_from_ccn(PyObject *self,
		PyObject *py_signed_info);

#endif	/* METHODS_SIGNEDINFO_H */
