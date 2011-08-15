// Utility function to print out character buffers and
// escape non-printable ASCII.

#include <Python.h>
#include <ccn/ccn.h>

#include <stdlib.h>
#include <stdio.h>

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