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

#ifndef METHODS_H
#  define	METHODS_H

PyObject *_pyccn_ccn_create(PyObject *UNUSED(self), PyObject *UNUSED(args));
PyObject *_pyccn_ccn_connect(PyObject *UNUSED(self), PyObject *py_ccn_handle);
PyObject *_pyccn_ccn_disconnect(PyObject *UNUSED(self),
		PyObject *py_ccn_handle);
PyObject *_pyccn_ccn_run(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_ccn_set_run_timeout(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_ccn_express_interest(PyObject *UNUSED(self),
		PyObject *args);
PyObject *_pyccn_ccn_set_interest_filter(PyObject *UNUSED(self),
		PyObject *args);
PyObject *_pyccn_ccn_get(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_ccn_put(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_ccn_get_default_key(PyObject *self, PyObject *arg);
PyObject *_pyccn_generate_RSA_key(PyObject *UNUSED(self), PyObject *args);
PyObject *_pyccn_SigningParams_from_ccn(PyObject *UNUSED(self),
		PyObject *py_signing_params);
PyObject *_pyccn_UpcallInfo_from_ccn(PyObject *UNUSED(self),
		PyObject *py_upcall_info);

#endif	/* METHODS_H */

