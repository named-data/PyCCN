/*
 * Copyright (c) 2011, Regents of the University of California
 * All rights reserved.
 * Written by: Jeff Burke <jburke@ucla.edu>
 *             Derek Kulinski <takeda@takeda.tk>
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

#ifndef _UTIL_H_
#  define	_UTIL_H_

#  if PY_MAJOR_VERSION >= 3
#    define _pyccn_STRING_CHECK(op) PyUnicode_Check(op)
#    define _pyccn_Int_Check(val) PyLong_Check(val)
#    define _pyccn_Int_FromLong(val) PyLong_FromLong(val)
#    define _pyccn_Int_AsLong(val) PyLong_AsLong(val)
#  else
#    define _pyccn_STRING_CHECK(op) (PyString_Check(op) || PyUnicode_Check(op))
#    define _pyccn_Int_Check(val) PyInt_Check(val)
#    define _pyccn_Int_FromLong(val) PyInt_FromLong(val)
#    define _pyccn_Int_AsLong(val) PyInt_AsLong(val)
#  endif


void dump_charbuf(struct ccn_charbuf* c, FILE* fp);
void panic(const char *message);
void print_object(const PyObject *object);
PyObject *_pyccn_unicode_to_utf8(PyObject *string, char **buffer,
		Py_ssize_t *length);

#endif	/* _UTIL_H_ */
