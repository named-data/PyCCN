/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

/*
 * util.c - utility functions
 */

#include "python_hdr.h"
#include <ccn/ccn.h>

#include <stdlib.h>
#include <stdio.h>

#include "pyccn.h"
#include "util.h"

void
dump_charbuf(struct ccn_charbuf *c, FILE * fp)
{
	for (size_t i = 0; i < c->length; i++) {
		if (isprint(c->buf[i]))
			putc(c->buf[i], fp);
		else
			fprintf(fp, "\\x%.2x", c->buf[i]);
	}
}

void
panic(const char *message)
{
	fprintf(stderr, "PANIC: %s\n", message);
	abort();
}

void
print_object(const PyObject *object)
{
	FILE *of = fopen("object.log", "aw");

	PyObject_Print((PyObject *) object, of, 0);
	putc('\n', of);
	PyObject_Print((PyObject *) object, of, Py_PRINT_RAW);
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
		assert(PyString_Check(string));

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

void *
_pyccn_run_state_add(struct ccn *handle, PyThreadState *thread_state)
{
	struct pyccn_state *pyccn_state = GETSTATE(_pyccn_module);
	struct pyccn_run_state *state;

	state = malloc(sizeof(struct pyccn_run_state));
	if (!state)
		return PyErr_NoMemory();

	state->handle = handle;
	state->thread_state = thread_state;
	state->next = pyccn_state->run_state;

	pyccn_state->run_state = state;

	return handle;
}

struct pyccn_run_state *
_pyccn_run_state_find(struct ccn *handle)
{
	struct pyccn_state *pyccn_state = GETSTATE(_pyccn_module);
	struct pyccn_run_state *p;

	for (p = pyccn_state->run_state; p; p = p->next) {
		if (p->handle != handle)
			continue;

		return p;
	}

	return NULL;
}

void
_pyccn_run_state_clear(void *handle)
{
	struct pyccn_state *pyccn_state = GETSTATE(_pyccn_module);
	struct pyccn_run_state *p, *q;

	p = pyccn_state->run_state;
	if (p->handle == handle) {
		pyccn_state->run_state = p->next;
		free(p);
		return;
	}

	for (q = p, p = p->next; p; q = p, p = p->next) {
		if (p->handle != handle)
			continue;

		q->next = p->next;
		free(p);
		return;
	}
}
