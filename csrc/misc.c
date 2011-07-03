// Utility function to print out character buffers and
// escape non-printable ASCII.

#include <stdio.h>
#include <ccn/ccn.h>

void
dump_charbuf(struct ccn_charbuf* c, FILE* fp)
{
	int i = 0;
	for (i = 0; i < c->length; i++) {
		if (c->buf[i] < 0x20 || c->buf[i] > 0x7E)
			fprintf(fp, "\\(%i)", c->buf[i]);
		else
			putc(c->buf[i], fp);
	}
}
