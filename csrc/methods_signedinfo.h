/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#ifndef METHODS_SIGNEDINFO_H
#  define	METHODS_SIGNEDINFO_H

PyObject *SignedInfo_obj_from_ccn(PyObject *py_signed_info);
PyObject *_pyccn_cmd_SignedInfo_to_ccn(PyObject *self, PyObject *args,
		PyObject *kwds);
PyObject *_pyccn_cmd_SignedInfo_obj_from_ccn(PyObject *self,
		PyObject *py_signed_info);

#endif	/* METHODS_SIGNEDINFO_H */
