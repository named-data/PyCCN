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

#ifndef OBJECTS_H
#  define	OBJECTS_H

#  if 0

struct completed_closure {
	PyObject *closure;
	struct completed_closure *next;
};
#  endif

enum _pyccn_capsules {
	CLOSURE = 1,
	CONTENT_OBJECT,
	CONTENT_OBJECT_COMPONENTS,
	EXCLUSION_FILTER,
	HANDLE,
	INTEREST,
	KEY_LOCATOR,
	NAME,
	PARSED_CONTENT_OBJECT,
	PARSED_INTEREST,
	PKEY_PRIV,
	PKEY_PUB,
	SIGNATURE,
	SIGNED_INFO,
	SIGNING_PARAMS,
	UPCALL_INFO
};

PyObject *CCNObject_New(enum _pyccn_capsules type, void *pointer);
PyObject *CCNObject_Borrow(enum _pyccn_capsules type, void *pointer);
int CCNObject_ReqType(enum _pyccn_capsules type, PyObject *capsule);
int CCNObject_IsValid(enum _pyccn_capsules type, PyObject *capsule);
void *CCNObject_Get(enum _pyccn_capsules type, PyObject *capsule);

PyObject *CCNObject_New_Closure(struct ccn_closure **closure);
PyObject *CCNObject_New_ParsedContentObject(
		struct ccn_parsed_ContentObject **pco);
PyObject *CCNObject_New_ContentObjectComponents(
		struct ccn_indexbuf **comps);
PyObject *CCNObject_New_charbuf(enum _pyccn_capsules type,
		struct ccn_charbuf **p);
void CCNObject_Complete_Closure(PyObject *py_closure);
void CCNObject_Purge_Closures();

#endif	/* OBJECTS_H */
