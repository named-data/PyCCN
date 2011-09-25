/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#ifndef METHODS_INTERESTS_H
#  define	METHODS_INTERESTS_H

PyObject *Interest_obj_from_ccn(PyObject *py_interest);
struct ccn_parsed_interest *_pyccn_interest_get_pi(PyObject *py_interest);
void _pyccn_interest_set_pi(PyObject *py_interest,
		struct ccn_parsed_interest *pi);
PyObject *_pyccn_cmd_Interest_obj_to_ccn(PyObject *UNUSED(self),
		PyObject *py_interest);
PyObject *_pyccn_cmd_Interest_obj_from_ccn(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_cmd_ExclusionFilter_names_to_ccn(PyObject *UNUSED(self),
		PyObject* args);
PyObject *_pyccn_cmd_ExclusionFilter_obj_from_ccn(PyObject *UNUSED(self),
		PyObject* args);

#endif	/* METHODS_INTERESTS_H */

