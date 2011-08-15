#include <Python.h>
#include <ccn/ccn.h>

#include "pyccn.h"
#include "objects.h"

#include "converters.h"

// ************
// SignedInfo
//
//


// Can be called directly from c library
//
// Pointer to a tagged blob starting with CCN_DTAG_SignedInfo
//

PyObject *
SignedInfo_obj_from_ccn(PyObject *py_signed_info)
{
	struct ccn_charbuf *signed_info;
	PyObject *py_obj_SignedInfo, *py_o;
	struct ccn_buf_decoder decoder, *d;
	size_t start, stop, size;
	const unsigned char *ptr;
	int r;

	signed_info = CCNObject_Get(SIGNED_INFO, py_signed_info);

	debug("SignedInfo_from_ccn start, size=%zd\n", signed_info->length);

	// 1) Create python object
	py_obj_SignedInfo = PyObject_CallObject(g_type_SignedInfo, NULL);
	if (!py_obj_SignedInfo)
		return NULL;

	// 2) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	r = PyObject_SetAttrString(py_obj_SignedInfo, "ccn_data", py_signed_info);
	JUMP_IF_NEG(r, error);

	// 3) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString
	// based on chk_signing_params
	// from ccn_client.c
	//
	//outputs:

	// Note, it is ok that non-filled optional elements
	// are initialized to None (through the .py file __init__)
	//

	d = ccn_buf_decoder_start(&decoder, signed_info->buf, signed_info->length);

	if (!ccn_buf_match_dtag(d, CCN_DTAG_SignedInfo)) {
		PyErr_Format(g_PyExc_CCNSignedInfoError, "Error finding"
				" CCN_DTAG_SignedInfo (decoder state: %d)", d->decoder.state);
		goto error;
	}

	ccn_buf_advance(d);

	/* PublisherPublic Key */
	//XXX: should we check for case when PublishePublicKeyDigest is not present? -dk
	start = d->decoder.token_index;
	ccn_parse_required_tagged_BLOB(d, CCN_DTAG_PublisherPublicKeyDigest,
			16, 64);
	stop = d->decoder.token_index;

	r = ccn_ref_tagged_BLOB(CCN_DTAG_PublisherPublicKeyDigest, d->buf, start,
			stop, &ptr, &size);
	if (r < 0) {
		PyErr_Format(g_PyExc_CCNSignedInfoError, "Error parsing"
				" CCN_DTAG_PublisherPublicKey (decoder state %d)",
				d->decoder.state);
		goto error;
	}

	//    self.publisherPublicKeyDigest = None     # SHA256 hash
	debug("PyObject_SetAttrString publisherPublicKeyDigest\n");
	py_o = PyByteArray_FromStringAndSize((const char*) ptr, size);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_SignedInfo, "publisherPublicKeyDigest",
			py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	/* Timestamp */
	start = d->decoder.token_index;
	ccn_parse_required_tagged_BLOB(d, CCN_DTAG_Timestamp, 1, -1);
	stop = d->decoder.token_index;

	r = ccn_ref_tagged_BLOB(CCN_DTAG_Timestamp, d->buf, start, stop, &ptr,
			&size);
	if (r < 0) {
		PyErr_Format(g_PyExc_CCNSignedInfoError, "Error parsing"
				" CCN_DTAG_Timestamp (decoder state %d)", d->decoder.state);
		goto error;
	}

	//    self.timeStamp = None   # CCNx timestamp
	debug("PyObject_SetAttrString timestamp\n");
	py_o = PyByteArray_FromStringAndSize((const char*) ptr, size);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_SignedInfo, "timestamp", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	/* Type */
	start = d->decoder.token_index;
	ccn_parse_optional_tagged_BLOB(d, CCN_DTAG_Type, 1, -1);
	stop = d->decoder.token_index;

	r = ccn_ref_tagged_BLOB(CCN_DTAG_Type, d->buf, start, stop, &ptr, &size);
	if (r == 0) {
		//    type = None   # CCNx type
		// TODO: Provide a string representation with the Base64 mnemonic?
		debug("PyObject_SetAttrString type\n");
		py_o = PyByteArray_FromStringAndSize((const char*) ptr, size);
		JUMP_IF_NULL(py_o, error);
		r = PyObject_SetAttrString(py_obj_SignedInfo, "type", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	/* FreshnessSeconds */
	r = ccn_parse_optional_tagged_nonNegativeInteger(d, CCN_DTAG_FreshnessSeconds);
	if (r >= 0) {
		//    self.freshnessSeconds = None
		debug("PyObject_SetAttrString freshnessSeconds\n");
		py_o = PyInt_FromLong(r);
		JUMP_IF_NULL(py_o, error);
		r = PyObject_SetAttrString(py_obj_SignedInfo, "freshnessSeconds", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	/* FinalBlockID */
#if 0 /* old code (left in case mine is wrong - dk) */
	if (ccn_buf_match_dtag(d, CCN_DTAG_FinalBlockID)) {
		ccn_buf_advance(d);
		start = d->decoder.token_index;
		if (ccn_buf_match_some_blob(d))
			ccn_buf_advance(d);
		stop = d->decoder.token_index;
		ccn_buf_check_close(d);
		if (d->decoder.state >= 0 && stop > start) {
			//    self.finalBlockID = None
			fprintf(stderr, "PyObject_SetAttrString finalBlockID, len=%zd\n", stop - start);
			py_o = PyByteArray_FromStringAndSize((const char*) (d->buf + start), stop - start);
			PyObject_SetAttrString(py_obj_SignedInfo, "finalBlockID", py_o);
			Py_INCREF(py_o);
		}
	}
#endif
	start = d->decoder.token_index;
	ccn_parse_optional_tagged_BLOB(d, CCN_DTAG_FinalBlockID, 1, -1);
	stop = d->decoder.token_index;

	r = ccn_ref_tagged_BLOB(CCN_DTAG_Type, d->buf, start, stop, &ptr, &size);
	if (r == 0) {
		//    self.finalBlockID = None
		debug("PyObject_SetAttrString finalBlockID, len=%zd\n", size);
		py_o = PyByteArray_FromStringAndSize((const char*) ptr, size);
		JUMP_IF_NULL(py_o, error);
		r = PyObject_SetAttrString(py_obj_SignedInfo, "finalBlockID", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	/* KeyLocator */
#if 0 /* Old code in case mine is wrong - dk */
	start = d->decoder.token_index;
	if (ccn_buf_match_dtag(d, CCN_DTAG_KeyLocator))
		ccn_buf_advance_past_element(d);
	stop = d->decoder.token_index;
	if (d->decoder.state >= 0 && stop > start) {
		fprintf(stderr, "PyObject_SetAttrString keyLocator, len=%zd\n", stop - start);
		struct ccn_charbuf* keyLocator = ccn_charbuf_create();
		ccn_charbuf_append(keyLocator, d->buf + start, stop - start);
		//    self.keyLocator = None
		py_o = KeyLocator_from_ccn(keyLocator); // it will free
		PyObject_SetAttrString(py_obj_SignedInfo, "keyLocator", py_o);
		Py_INCREF(py_o);
	}
#endif

	/*
	 * KeyLocator is not a BLOB, but an another structure, this requires
	 * us to parse it differently
	 */
	start = d->decoder.token_index;
	if (ccn_buf_match_dtag(d, CCN_DTAG_KeyLocator)) {
		r = ccn_buf_advance_past_element(d);
		if (r < 0) {
			PyErr_Format(g_PyExc_CCNSignedInfoError, "Error locating"
					" CCN_DTAG_KeyLocator (decoder state: %d, r: %d)",
					d->decoder.state, r);
			goto error;
		}
		stop = d->decoder.token_index;
		/*
				debug("element_index = %zd size = %zd nest = %d numval = %zd state = %d"
						" token_index %zd\n",
						d->decoder.element_index, d->decoder.index, d->decoder.nest,
						d->decoder.numval, d->decoder.state, d->decoder.token_index);
				assert(d->decoder.state >= 0);
		 */

		ptr = d->buf + start;
		size = stop - start;
		assert(size > 0);

		//TODO: Change to an CCNObject object
		struct ccn_charbuf *key_locator;

		debug("PyObject_SetAttrString keyLocator, len=%zd\n", size);
		key_locator = ccn_charbuf_create();
		JUMP_IF_NULL_MEM(key_locator, error);

		r = ccn_charbuf_append(key_locator, ptr, size);
		if (r < 0) {
			PyErr_NoMemory();
			ccn_charbuf_destroy(&key_locator);
			goto error;
		}

		//    self.keyLocator = None
		py_o = KeyLocator_from_ccn(key_locator);
		//XXX: Py_DECREF(py_key_locator);
		JUMP_IF_NULL(py_o, error);
		r = PyObject_SetAttrString(py_obj_SignedInfo, "keyLocator", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	ccn_buf_check_close(d);
	if (d->decoder.state < 0) {
		PyErr_Format(g_PyExc_CCNSignedInfoError, "SignedInfo decoding error"
				" (decoder state: %d, numval: %d)", d->decoder.state,
				d->decoder.numval);
		goto error;
	}

	// 4) Return the created object
	debug("SignedInfo_from_ccn ends\n");
	return py_obj_SignedInfo;

error:
	Py_DECREF(py_obj_SignedInfo);

	return NULL;
}

PyObject *
_pyccn_SignedInfo_to_ccn(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"pubkey_digest", "type", "timestamp",
		"freshness", "final_block_id", "key_locator", NULL};

	PyObject *py_pubkey_digest, *py_timestamp = NULL, *py_final_block = NULL,
			*py_key_locator = NULL;
	struct ccn_charbuf *si;
	int r;
	size_t publisher_key_id_size;
	const void *publisher_key_id;
	int type, freshness = -1;
	struct ccn_charbuf *timestamp, *finalblockid, *key_locator;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oi|OiOO", kwlist,
			&py_pubkey_digest, &type, &py_timestamp, &freshness,
			&py_final_block, &py_key_locator))
		return NULL;

	if (!PyByteArray_Check(py_pubkey_digest)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a ByteArray as pubkey_digest");
		return NULL;
	} else {
		publisher_key_id_size = PyByteArray_GET_SIZE(py_pubkey_digest);
		publisher_key_id = PyByteArray_AS_STRING(py_pubkey_digest);
	}

	if (py_timestamp && py_timestamp != Py_None) {
		PyErr_SetString(PyExc_NotImplementedError, "Timestamp is not implemented yet");
		return NULL;
	} else
		timestamp = NULL;

	if (py_final_block && py_final_block != Py_None) {
		PyErr_SetString(PyExc_NotImplementedError, "Final Block ID is not implemented yet");
		return NULL;
	} else
		finalblockid = NULL;

	if (!py_key_locator || py_key_locator == Py_None)
		key_locator = NULL;
	else if (CCNObject_IsValid(KEY_LOCATOR, py_key_locator))
		key_locator = CCNObject_Get(KEY_LOCATOR, py_key_locator);
	else {
		PyErr_SetString(PyExc_TypeError, "key_locator needs to be a CCN KeyLocator object");
		return NULL;
	}

	si = ccn_charbuf_create();
	if (!si)
		return PyErr_NoMemory();

	r = ccn_signed_info_create(si, publisher_key_id, publisher_key_id_size,
			timestamp, type, freshness, finalblockid, key_locator);
	fprintf(stderr, "ccn_signed_info_create res=%d\n", r);

	if (r < 0) {
		ccn_charbuf_destroy(&si);
		PyErr_SetString(g_PyExc_CCNError, "Error while creating SignedInfo");

		return NULL;
	}

	return CCNObject_New(SIGNED_INFO, si);
}

// From within python
//

PyObject *
_pyccn_SignedInfo_from_ccn(PyObject *self, PyObject *py_signed_info)
{
	if (!CCNObject_IsValid(SIGNED_INFO, py_signed_info)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing"
				" a struct ccn_charbuf*");
		return NULL;
	}

	return SignedInfo_obj_from_ccn(py_signed_info);
}
