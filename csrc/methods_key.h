/*
 * Copyright (c) 2011, Regents of the University of California
 * All rights reserved.
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Regents of the University of California nor
 *       the names of its contributors may be used to endorse or promote
 *       products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL REGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
PyObject *_pyccn_PEM_read_key(PyObject *self, PyObject *args);
PyObject *_pyccn_PEM_write_key(PyObject *self, PyObject *args,
		PyObject *py_kwrds);

#endif	/* METHODS_KEY_H */

