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

#include "python.h"
#include <ccn/ccn.h>

#include "pyccn.h"
#include "objects.h"
#include "util.h"

/* only used by assertions code */
#ifndef NDEBUG
#    include <string.h>
#endif

static int
append_digest_algorithm(struct ccn_charbuf *signature,
		PyObject *py_obj_Signature)
{
	PyObject *py_digestAlgorithm = NULL;
	PyObject *py_o;
	char *str;
	Py_ssize_t str_len;
	int r;

	if (!PyObject_HasAttrString(py_obj_Signature, "digestAlgorithm"))
		return 0;

	py_digestAlgorithm = PyObject_GetAttrString(py_obj_Signature,
			"digestAlgorithm");
	JUMP_IF_NULL(py_digestAlgorithm, error);

	if (py_digestAlgorithm != Py_None) {
		py_o = _pyccn_unicode_to_utf8(py_digestAlgorithm, &str, &str_len);
		assert((Py_ssize_t) strlen(str) == str_len);
		JUMP_IF_NULL(py_o, error);

		r = ccnb_append_tagged_blob(signature, CCN_DTAG_DigestAlgorithm,
				str, str_len);
		Py_DECREF(py_o);
		JUMP_IF_NEG_MEM(r, error);
	}
	Py_DECREF(py_digestAlgorithm);

	return 0;

error:
	Py_XDECREF(py_digestAlgorithm);
	return -1;
}

static int
append_witness(struct ccn_charbuf *signature, PyObject *py_obj_Signature)
{
	PyObject *py_witness = NULL;
	const char *blob;
	Py_ssize_t blobsize;
	int r;

	if (!PyObject_HasAttrString(py_obj_Signature, "witness"))
		return 0;

	py_witness = PyObject_GetAttrString(py_obj_Signature, "witness");
	JUMP_IF_NULL(py_witness, error);

	if (py_witness != Py_None) {
		blob = PyByteArray_AsString(py_witness);
		JUMP_IF_NULL(blob, error);
		blobsize = PyByteArray_GET_SIZE(py_witness);

		debug("witness blobsize = %zd\n", blobsize);

		r = ccnb_append_tagged_blob(signature, CCN_DTAG_Witness, blob,
				blobsize);
		JUMP_IF_NEG_MEM(r, error);
	}
	Py_DECREF(py_witness);

	return 0;

error:
	Py_XDECREF(py_witness);
	return -1;
}

static int
append_signature_bits(struct ccn_charbuf *signature,
		PyObject *py_obj_Signature)
{
	PyObject *py_signatureBits = NULL;
	const char *blob;
	Py_ssize_t blobsize;
	int r;

	if (!PyObject_HasAttrString(py_obj_Signature, "signatureBits"))
		return 0;

	py_signatureBits = PyObject_GetAttrString(py_obj_Signature,
			"signatureBits");
	JUMP_IF_NULL(py_signatureBits, error);

	if (py_signatureBits != Py_None) {
		blob = PyByteArray_AsString(py_signatureBits);
		JUMP_IF_NULL(blob, error);
		blobsize = PyByteArray_GET_SIZE(py_signatureBits);

		r = ccnb_append_tagged_blob(signature, CCN_DTAG_SignatureBits, blob,
				blobsize);
		JUMP_IF_NEG_MEM(r, error);
	}
	Py_DECREF(py_signatureBits);

	return 0;

error:
	Py_XDECREF(py_signatureBits);
	return -1;
}

static PyObject *
obj_Signature_to_ccn(PyObject *py_obj_Signature)
{
	struct ccn_charbuf *signature;
	PyObject *py_signature;
	int r;

	debug("Signature_to_ccn starts \n");

	py_signature = CCNObject_New_charbuf(SIGNATURE, &signature);
	JUMP_IF_NULL(py_signature, error);

	r = ccn_charbuf_append_tt(signature, CCN_DTAG_Signature, CCN_DTAG);
	JUMP_IF_NEG_MEM(r, error);

	r = append_digest_algorithm(signature, py_obj_Signature);
	JUMP_IF_NEG(r, error);

	r = append_witness(signature, py_obj_Signature);
	JUMP_IF_NEG(r, error);

	r = append_signature_bits(signature, py_obj_Signature);
	JUMP_IF_NEG(r, error);

	r = ccn_charbuf_append_closer(signature); /* </Signature> */
	JUMP_IF_NEG_MEM(r, error);

	return py_signature;

error:
	Py_XDECREF(py_signature);
	return NULL;
}
// Can be called directly from c library

PyObject *
obj_Signature_obj_from_ccn(PyObject *py_signature)
{
	struct ccn_charbuf *signature;
	PyObject *py_obj_signature, *py_o;
	struct ccn_buf_decoder decoder, *d;
	size_t start, stop, size;
	const unsigned char *ptr;
	int r;

	assert(CCNObject_IsValid(SIGNATURE, py_signature));
	signature = CCNObject_Get(SIGNATURE, py_signature);

	debug("Signature_from_ccn start, len=%zd\n", signature->length);

	// 1) Create python object
	py_obj_signature = PyObject_CallObject(g_type_Signature, NULL);
	if (!py_obj_signature)
		return NULL;

	// 2) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	r = PyObject_SetAttrString(py_obj_signature, "ccn_data", py_signature);
	JUMP_IF_NEG(r, error);

	// 3) Parse c structure and fill python attributes

	// Neither DigestAlgorithm nor Witness are included in the packet
	// from ccnput, so they are apparently both optional
	d = ccn_buf_decoder_start(&decoder, signature->buf, signature->length);

	if (!ccn_buf_match_dtag(d, CCN_DTAG_Signature)) {
		PyErr_Format(g_PyExc_CCNSignatureError, "Error finding"
				" CCN_DTAG_Signature (decoder state: %d)", d->decoder.state);
		goto error;
	}

	debug("Is a signature\n");
	ccn_buf_advance(d);

	/* CCN_DTAG_DigestAlgorithm */
	start = d->decoder.token_index;
	ccn_parse_optional_tagged_BLOB(d, CCN_DTAG_DigestAlgorithm, 1, -1);
	stop = d->decoder.token_index;

	r = ccn_ref_tagged_BLOB(CCN_DTAG_DigestAlgorithm, d->buf, start, stop,
			&ptr, &size);
	if (r == 0) {
		debug("PyObject_SetAttrString digestAlgorithm\n");
		py_o = PyByteArray_FromStringAndSize((const char*) ptr, size);
		JUMP_IF_NULL(py_o, error);
		r = PyObject_SetAttrString(py_obj_signature, "digestAlgorithm", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	/* CCN_DTAG_Witness */
	start = d->decoder.token_index;
	ccn_parse_optional_tagged_BLOB(d, CCN_DTAG_Witness, 1, -1);
	stop = d->decoder.token_index;
	debug("witness start %zd stop %zd\n", start, stop);

	r = ccn_ref_tagged_BLOB(CCN_DTAG_Witness, d->buf, start, stop, &ptr, &size);
	if (r == 0) {
		// The Witness is represented as a DER-encoded PKCS#1 DigestInfo,
		// which contains an AlgorithmIdentifier (an OID, together with any necessary parameters)
		// and a byte array (OCTET STRING) containing the digest information to be interpreted according to that OID.
		// http://www.ccnx.org/releases/latest/doc/technical/SignatureGeneration.html
		debug("PyObject_SetAttrString witness\n");
		py_o = PyByteArray_FromStringAndSize((const char*) ptr, size);
		JUMP_IF_NULL(py_o, error);
		r = PyObject_SetAttrString(py_obj_signature, "witness", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	/* CCN_DTAG_SignatureBits */
	start = d->decoder.token_index;
	ccn_parse_required_tagged_BLOB(d, CCN_DTAG_SignatureBits, 1, -1);
	stop = d->decoder.token_index;

	r = ccn_ref_tagged_BLOB(CCN_DTAG_SignatureBits, d->buf, start, stop, &ptr,
			&size);
	if (r < 0) {
		PyErr_Format(g_PyExc_CCNSignatureError, "Error parsing"
				" CCN_DTAG_SignatureBits (decoder state %d)", d->decoder.state);
		goto error;
	}

	assert(r == 0);
	debug("PyObject_SetAttrString signatureBits\n");
	py_o = PyByteArray_FromStringAndSize((const char*) ptr, size);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_signature, "signatureBits", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	ccn_buf_check_close(d);
	if (d->decoder.state < 0) {
		PyErr_Format(g_PyExc_CCNSignatureError, "Signature decoding error"
				" (decoder state: %d, numval: %d)", d->decoder.state,
				d->decoder.numval);
		goto error;
	}

	// 4) Return the created object
	debug("Signature_from_ccn ends\n");
	return py_obj_signature;

error:
	Py_DECREF(py_obj_signature);
	return NULL;
}

PyObject *
_pyccn_Signature_to_ccn(PyObject *UNUSED(self), PyObject *py_obj_Signature)
{
	if (strcmp(py_obj_Signature->ob_type->tp_name, "Signature") != 0) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Signature");

		return NULL;
	}

	return obj_Signature_to_ccn(py_obj_Signature);
}

PyObject *
_pyccn_Signature_from_ccn(PyObject *UNUSED(self), PyObject *py_signature)
{
	if (!CCNObject_IsValid(SIGNATURE, py_signature)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN object containing"
				" signature");
		return NULL;
	}

	return obj_Signature_obj_from_ccn(py_signature);
}
