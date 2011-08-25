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

/*
 * util.c - utility functions
 */

#include "python.h"
#include <ccn/ccn.h>

#include <stdlib.h>
#include <stdio.h>

#include "pyccn.h"

void
dump_charbuf(struct ccn_charbuf *c, FILE * fp)
{
	for (size_t i = 0; i < c->length; i++) {
		if (isprint(c->buf[i]))
			putc(c->buf[i], fp);
		else
			fprintf(fp, "\\(%i)", c->buf[i]);
	}
}

void
panic(const char *message)
{
	fprintf(stderr, "PANIC: %s\n", message);
	abort();
}

void
print_object(PyObject *object)
{
	FILE *of = fopen("object.log", "aw");

	PyObject_Print(object, of, 0);
	putc('\n', of);
	PyObject_Print(object, of, Py_PRINT_RAW);
	putc('\n', of);
	putc('\n', of);

	fclose(of);
}

PyObject *
_pyccn_unicode_to_utf8(PyObject *string, char **buffer, Py_ssize_t *length)
{
	PyObject *py_utf8;
	int r;

#if PY_MAJOR_VERSION < 3
	if (!PyUnicode_Check(string)) {
		r = PyString_AsStringAndSize(string, buffer, length);
		if (r < 0)
			return NULL;

		Py_INCREF(string);
		return string;
	}
#endif

	assert(PyUnicode_Check(string));

	py_utf8 = PyUnicode_EncodeUTF8(PyUnicode_AS_UNICODE(string),
			PyUnicode_GET_SIZE(string), NULL);
	if (!py_utf8)
		return NULL;

	r = PyBytes_AsStringAndSize(py_utf8, buffer, length);
	if (r < 0) {
		Py_DECREF(py_utf8);
		return NULL;
	}

	return py_utf8;
}

FILE *
_pyccn_open_file_handle(PyObject *py_file, const char *mode)
{
	FILE *handle;
	int ofd, fd = -1;

	ofd = PyObject_AsFileDescriptor(py_file);
	JUMP_IF_NEG(ofd, error);

	fd = dup(ofd);
	JUMP_IF_NEG(fd, errno_error);

	handle = fdopen(fd, mode);
	JUMP_IF_NULL(handle, errno_error);

	return handle;

errno_error:
	PyErr_SetFromErrno(PyExc_IOError);
error:
	if (fd > -1)
		close(fd);
	return NULL;
}

int
_pyccn_close_file_handle(FILE *fh)
{
	return fclose(fh);
}
