/*
 * File:   medhods_contentobject.h
 * Author: takeda
 *
 * Created on August 8, 2011, 1:43 AM
 */

#ifndef MEDHODS_CONTENTOBJECT_H
#  define	MEDHODS_CONTENTOBJECT_H

PyObject *ContentObject_from_ccn_parsed(PyObject *py_content_object,
		PyObject *py_parsed_content_object, PyObject *py_components);
PyObject *_pyccn_content_to_bytearray(PyObject *self, PyObject *arg);
PyObject *_pyccn_ContentObject_to_ccn(PyObject *self, PyObject *args);
PyObject *_pyccn_ContentObject_from_ccn(PyObject *self, PyObject *args);

#endif	/* MEDHODS_CONTENTOBJECT_H */

