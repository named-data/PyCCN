/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#include "python_hdr.h"
#include <ccn/ccn.h>
#include <ccn/signing.h>

#include "pyccn.h"
#include "util.h"
#include "key_utils.h"
#include "methods_key.h"
#include "methods_name.h"
#include "objects.h"

#if 0

static struct ccn_keystore*
Key_to_ccn_keystore(PyObject* py_key)
{
	// An imperfect conversion here, but...

	// This is supposed to be an opaque type.
	// We borrow this from ccn_keystore.c
	// so that we can work with the ccn hashtable
	// and do Key_to_keystore... but this whole method may not be
	// ever needed, as the ccn_keystore type seems
	// to be primarily for the use of the library internally?

	struct ccn_keystore_private {
		int initialized;
		EVP_PKEY *private_key;
		EVP_PKEY *public_key;
		X509 *certificate;
		ssize_t pubkey_digest_length;
		unsigned char pubkey_digest[SHA256_DIGEST_LENGTH];
	};


	struct ccn_keystore_private* keystore = calloc(1, sizeof(struct ccn_keystore_private));
	keystore->initialized = 1;
	// TODO: need to INCREF here?
	keystore->private_key = (EVP_PKEY*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_key, "ccn_data_private"));
	keystore->public_key = (EVP_PKEY*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_key, "ccn_data_public"));

	RSA* private_key_rsa = EVP_PKEY_get1_RSA((EVP_PKEY*) keystore->private_key);
	unsigned char* public_key_digest;
	size_t public_key_digest_len;
	create_public_key_digest(private_key_rsa, &public_key_digest, &public_key_digest_len);
	memcpy(keystore->pubkey_digest, public_key_digest, public_key_digest_len);
	keystore->pubkey_digest_length = public_key_digest_len;
	free(public_key_digest);
	free(private_key_rsa);
	return(struct ccn_keystore*) keystore;

}
#endif

// ************
// KeyLocator
//
//

static int
KeyLocator_name_to_ccn(struct ccn_charbuf *keylocator, PyObject *py_name)
{
	struct ccn_charbuf *name;
	int r;

	if (!CCNObject_IsValid(NAME, py_name)) {
		PyErr_SetString(PyExc_TypeError, "Argument needs to be of type CCN Name");
		return -1;
	}
	name = CCNObject_Get(NAME, py_name);

	r = ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyName, CCN_DTAG);
	JUMP_IF_NEG_MEM(r, error);

	// Looks like name already has all necessary tags
	// r = ccnb_append_tagged_blob(keylocator, CCN_DTAG_Name, name->buf, name->length); // check
	r = ccn_charbuf_append_charbuf(keylocator, name);
	JUMP_IF_NEG_MEM(r, error);

	r = ccn_charbuf_append_closer(keylocator); /* </KeyName> */
	JUMP_IF_NEG_MEM(r, error);

	r = 0;

error:

	return r;
}

static int
KeyLocator_key_to_ccn(struct ccn_charbuf *keylocator, PyObject *py_key)
{
	struct ccn_pkey *key;
	int r;

	if (!CCNObject_IsValid(PKEY_PUB, py_key)) {
		PyErr_SetString(PyExc_TypeError, "Argument needs to be of type CCN Key");
		return -1;
	}

	key = CCNObject_Get(PKEY_PUB, py_key);

	r = ccn_charbuf_append_tt(keylocator, CCN_DTAG_Key, CCN_DTAG);
	JUMP_IF_NEG_MEM(r, error);

	r = ccn_append_pubkey_blob(keylocator, key);
	JUMP_IF_NEG_MEM(r, error);

	r = ccn_charbuf_append_closer(keylocator); /* </Key> */
	JUMP_IF_NEG_MEM(r, error);

	r = 0;

error:

	return r;
}

struct ccn_pkey *
Key_to_ccn_private(PyObject *py_key)
{
	PyObject *capsule;
	struct ccn_pkey *key;

	capsule = PyObject_GetAttrString(py_key, "ccn_data_private");
	assert(capsule);
	key = CCNObject_Get(PKEY_PRIV, capsule);
	Py_DECREF(capsule);

	return key;
}

// Can be called directly from c library
// Note that this isn't the wire format, so we
// do a potentially redundant step here and regenerate the DER format
// so that we can do the key hash

PyObject *
Key_obj_from_ccn(PyObject *py_key_ccn)
{
	struct ccn_pkey *key_ccn;
	PyObject *py_obj_Key;
	RSA *private_key_rsa = NULL;
	PyObject *py_private_key_ccn = NULL, *py_public_key_ccn = NULL,
			*py_public_key_digest = NULL;
	int public_key_digest_len;
	int r, public_only;
	PyObject* py_o;

	assert(g_type_Key);

	debug("Key_from_ccn start\n");

	if (CCNObject_IsValid(PKEY_PRIV, py_key_ccn)) {
		public_only = 0;
		key_ccn = CCNObject_Get(PKEY_PRIV, py_key_ccn);
	} else if (CCNObject_IsValid(PKEY_PUB, py_key_ccn)) {
		public_only = 1;
		key_ccn = CCNObject_Get(PKEY_PUB, py_key_ccn);
	} else {
		PyErr_SetString(PyExc_TypeError, "expected CCN key");
		return NULL;
	}

	// 1) Create python object
	py_obj_Key = PyObject_CallObject(g_type_Key, NULL);
	JUMP_IF_NULL(py_obj_Key, error);

	// 2) Parse c structure and fill python attributes

	// If this is a private key, split private and public keys
	// There is probably a less convoluted way to do this than pulling
	// it out to RSA
	// Also, create the digest...
	// These non-ccn functions assume the CCN defaults, RSA + SHA256
	private_key_rsa = ccn_key_to_rsa(key_ccn);
	JUMP_IF_NULL(private_key_rsa, error);

	r = ccn_keypair_from_rsa(public_only, private_key_rsa, &py_private_key_ccn,
			&py_public_key_ccn);
	JUMP_IF_NEG(r, error);

	r = create_public_key_digest(private_key_rsa, &py_public_key_digest,
			&public_key_digest_len);
	RSA_free(private_key_rsa);
	private_key_rsa = NULL;
	JUMP_IF_NEG(r, error);

	//  ccn_digest has a more convoluted API, with examples
	// in ccn_client, but *for now* it boils down to the same thing.

	/* type */
	py_o = PyUnicode_FromString("RSA");
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_obj_Key, "type", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	/* publicKeyID */
	r = PyObject_SetAttrString(py_obj_Key, "publicKeyID", py_public_key_digest);
	Py_CLEAR(py_public_key_digest);
	JUMP_IF_NEG(r, error);

	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	// privateKey
	r = PyObject_SetAttrString(py_obj_Key, "ccn_data_private",
			py_private_key_ccn);
	Py_CLEAR(py_private_key_ccn);
	JUMP_IF_NEG(r, error);

	// publicKey
	r = PyObject_SetAttrString(py_obj_Key, "ccn_data_public",
			py_public_key_ccn);
	Py_CLEAR(py_public_key_ccn);
	JUMP_IF_NEG(r, error);

	// 4) Return the created object

	debug("Key_from_ccn ends\n");

	return py_obj_Key;

error:
	Py_XDECREF(py_private_key_ccn);
	Py_XDECREF(py_public_key_ccn);
	Py_XDECREF(py_public_key_digest);
	RSA_free(private_key_rsa);
	Py_XDECREF(py_obj_Key);
	return NULL;
}

// Can be called directly from c library
//
//	Certificate is not supported yet, as it doesn't seem to be in CCNx.
//

PyObject *
KeyLocator_obj_from_ccn(PyObject *py_keylocator)
{
	struct ccn_buf_decoder decoder, *d;
	struct ccn_charbuf *keylocator;
	struct ccn_charbuf *name;
	struct ccn_pkey *pubkey;
	size_t start, stop;
	int r;
	PyObject *py_o;
	PyObject *py_KeyLocator_obj = NULL;

	keylocator = CCNObject_Get(KEY_LOCATOR, py_keylocator);

	debug("KeyLocator_from_ccn start\n");

	d = ccn_buf_decoder_start(&decoder, keylocator->buf, keylocator->length);
	assert(d); //should always succeed

	if (!ccn_buf_match_dtag(d, CCN_DTAG_KeyLocator)) {
		PyErr_SetString(g_PyExc_CCNKeyLocatorError, "The input isn't a valid"
				" KeyLocator");
		return NULL;
	}
	ccn_buf_advance(d);

	if (ccn_buf_match_dtag(d, CCN_DTAG_KeyName)) {
		const unsigned char *bname;
		size_t bname_size;
		PyObject *py_name_obj;

		ccn_buf_advance(d);

		start = d->decoder.token_index;
		r = ccn_parse_Name(d, NULL);
		stop = d->decoder.token_index;
		if (r < 0)
			return PyErr_Format(g_PyExc_CCNKeyLocatorError, "Error finding"
				" CCN_DTAG_Name for KeyName (decoder state: %d)",
				d->decoder.state);

		assert(stop > start);
		bname_size = stop - start;
		bname = d->buf + start;
		/*
				r = ccn_ref_tagged_BLOB(CCN_DTAG_Name, d->buf, start, stop, &bname,
						&bname_size);
				if (r < 0)
					return PyErr_Format(g_PyExc_CCNKeyLocatorError, "Error getting"
						" CCN_DTAG_Name BLOB for KeyName (decoder state: %d)",
						d->decoder.state);
		 */

		debug("Parse CCN_DTAG_Name inside KeyName, len=%zd\n", bname_size);

		py_o = CCNObject_New_charbuf(NAME, &name);
		if (!py_o)
			return NULL;

		r = ccn_charbuf_append(name, bname, bname_size);
		if (r < 0) {
			Py_DECREF(py_o);
			return PyErr_NoMemory();
		}

		py_name_obj = Name_obj_from_ccn(py_o);
		Py_DECREF(py_o);
		if (!py_name_obj)
			return NULL;

		py_KeyLocator_obj = PyObject_CallObject(g_type_KeyLocator, NULL);
		if (!py_KeyLocator_obj) {
			Py_DECREF(py_name_obj);
			goto error;
		}

		r = PyObject_SetAttrString(py_KeyLocator_obj, "keyName", py_name_obj);
		Py_DECREF(py_name_obj);
		JUMP_IF_NEG(r, error);

#pragma message "Parse and add digest to the keylocator"
	} else if (ccn_buf_match_dtag(d, CCN_DTAG_Key)) {
		const unsigned char *dkey;
		size_t dkey_size;
		PyObject *py_key_obj, *py_ccn_key;

		start = d->decoder.token_index;
		r = ccn_parse_required_tagged_BLOB(d, CCN_DTAG_Key, 1, -1);
		stop = d->decoder.token_index;
		if (r < 0)
			return PyErr_Format(g_PyExc_CCNKeyLocatorError, "Error finding"
				" CCN_DTAG_Key for Key (decoder state: %d)", d->decoder.state);

		r = ccn_ref_tagged_BLOB(CCN_DTAG_Key, d->buf, start, stop, &dkey,
				&dkey_size);
		if (r < 0)
			return PyErr_Format(g_PyExc_CCNKeyLocatorError, "Error getting"
				" CCN_DTAG_Key BLOB for Key (decoder state: %d)",
				d->decoder.state);

		debug("Parse CCN_DTAG_Key, len=%zd\n", dkey_size);

		pubkey = ccn_d2i_pubkey(dkey, dkey_size); // free with ccn_pubkey_free()
		if (!pubkey) {
			PyErr_SetString(g_PyExc_CCNKeyLocatorError, "Unable to parse key to"
					" internal representation");
			return NULL;
		}
		py_ccn_key = CCNObject_New(PKEY_PUB, pubkey);
		if (!py_ccn_key) {
			ccn_pubkey_free(pubkey);
			return NULL;
		}

		py_key_obj = Key_obj_from_ccn(py_ccn_key);
		Py_DECREF(py_ccn_key);
		if (!py_key_obj)
			return NULL;

		py_KeyLocator_obj = PyObject_CallObject(g_type_KeyLocator, NULL);
		if (!py_KeyLocator_obj) {
			Py_DECREF(py_key_obj);
			goto error;
		}

		r = PyObject_SetAttrString(py_KeyLocator_obj, "key", py_key_obj);
		Py_DECREF(py_key_obj);
		JUMP_IF_NEG(r, error);
	} else if (ccn_buf_match_dtag(d, CCN_DTAG_Certificate)) {
		PyErr_SetString(PyExc_NotImplementedError, "Found certificate DTAG,"
				" which currently is unsupported");
		return NULL;
	} else {
		PyErr_SetString(g_PyExc_CCNKeyLocatorError, "Unknown KeyLocator Type");
		return NULL;
	}

	ccn_buf_check_close(d); // we don't really check the parser, though-

	return py_KeyLocator_obj;

error:
	Py_XDECREF(py_KeyLocator_obj);
	return NULL;
}

/*
 * From within python
 */

PyObject *
_pyccn_cmd_Key_obj_from_ccn(PyObject *UNUSED(self), PyObject *py_ccn_key)
{
	return Key_obj_from_ccn(py_ccn_key);
}

PyObject *
_pyccn_cmd_KeyLocator_to_ccn(PyObject *UNUSED(self), PyObject *args,
		PyObject *kwds)
{
	static char *kwlist[] = {"name", "digest", "key", "cert", NULL};
	PyObject *py_name = Py_None, *py_digest = Py_None, *py_key = Py_None,
			*py_cert = Py_None;
	struct ccn_charbuf *keylocator;
	int r;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOOO", kwlist, &py_name,
			&py_digest, &py_key, &py_cert))
		return NULL;

	keylocator = ccn_charbuf_create();
	JUMP_IF_NULL_MEM(keylocator, error);

	r = ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyLocator, CCN_DTAG);
	JUMP_IF_NEG_MEM(r, error);

	if (py_name != Py_None) {
		//TODO: add digest as well
		r = KeyLocator_name_to_ccn(keylocator, py_name);
		JUMP_IF_NEG(r, error);
	} else if (py_key != Py_None) {
		r = KeyLocator_key_to_ccn(keylocator, py_key);
		JUMP_IF_NEG(r, error);
	} else if (py_cert != Py_None) {
#if 0
		ccn_charbuf_append_tt(keylocator, CCN_DTAG_Certificate, CCN_DTAG);
		// TODO: How to handle certificate?  ** Not supported here
		ccn_charbuf_append_closer(keylocator); /* </Certificate> */
#endif

		PyErr_SetString(PyExc_NotImplementedError, "Certificate key locator is"
				" not implemented");
		goto error;
	}

	r = ccn_charbuf_append_closer(keylocator); /* </KeyLocator> */
	JUMP_IF_NEG_MEM(r, error);

	return CCNObject_New(KEY_LOCATOR, keylocator);
error:
	ccn_charbuf_destroy(&keylocator);

	return NULL;
}

PyObject *
_pyccn_cmd_KeyLocator_obj_from_ccn(PyObject *UNUSED(self), PyObject *py_keylocator)
{
	if (!CCNObject_IsValid(KEY_LOCATOR, py_keylocator)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Key Locator object");

		return NULL;
	}

	return KeyLocator_obj_from_ccn(py_keylocator);
}

PyObject *
_pyccn_cmd_PEM_read_key(PyObject *UNUSED(self), PyObject *args,
		PyObject *py_kwds)
{
	PyObject *py_file = Py_None, *py_private_pem = Py_None,
			*py_public_pem = Py_None;
	PyObject *py_private_key, *py_public_key, *py_digest, *py_ret;
	int digest_len, r;
	FILE *fin;

	static char *kwlist[] = {"file", "private", "public", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, py_kwds, "|OOO", kwlist, &py_file,
			&py_private_pem, &py_public_pem))
		return NULL;

	if (py_file != Py_None) {
		fin = _pyccn_open_file_handle(py_file, "r");
		if (!fin)
			return NULL;

		r = read_key_pem(fin, &py_private_key, &py_public_key, &py_digest,
				&digest_len);
		_pyccn_close_file_handle(fin);
		if (r < 0)
			return NULL;
	} else if (py_private_pem != Py_None) {
		r = put_key_pem(0, py_private_pem, &py_private_key, &py_public_key,
				&py_digest);
		if (r < 0)
			return NULL;
	} else if (py_public_pem != Py_None) {
		r = put_key_pem(1, py_public_pem, &py_private_key, &py_public_key,
				&py_digest);
		if (r < 0)
			return NULL;
	} else {
		PyErr_SetString(PyExc_TypeError, "expected file handle or key in PEM"
				" format");
		return NULL;
	}

	py_ret = Py_BuildValue("(OOO)", py_private_key, py_public_key, py_digest);
	Py_DECREF(py_private_key);
	Py_DECREF(py_public_key);
	Py_DECREF(py_digest);

	return py_ret;
}

PyObject *
_pyccn_cmd_PEM_write_key(PyObject *UNUSED(self), PyObject *args,
		PyObject *py_kwds)
{
	PyObject *py_pkey, *py_file = Py_None;
	struct ccn_pkey *pkey;
	FILE *of;
	int r;
	int private = -1;

	static char *kwlist[] = {"key", "file", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, py_kwds, "O|O", kwlist, &py_pkey,
			&py_file))
		return NULL;

	if (CCNObject_IsValid(PKEY_PRIV, py_pkey)) {
		private = 1;
		pkey = CCNObject_Get(PKEY_PRIV, py_pkey);
	} else if (CCNObject_IsValid(PKEY_PUB, py_pkey)) {
		private = 0;
		pkey = CCNObject_Get(PKEY_PUB, py_pkey);
	} else {
		PyErr_SetString(PyExc_TypeError, "Argument needs to be a CCN PKEY");
		return NULL;
	}

	assert(private >= 0 && private <= 1);

	if (py_file != Py_None) {
		of = _pyccn_open_file_handle(py_file, "w");
		if (!of)
			return NULL;

		if (private)
			r = write_key_pem_private(of, pkey);
		else
			r = write_key_pem_public(of, pkey);

		_pyccn_close_file_handle(of);
		if (r < 0)
			return NULL;
	} else {
		if (private)
			return get_key_pem_private(pkey);
		else
			return get_key_pem_public(pkey);
	}

	Py_RETURN_NONE;
}

PyObject *
_pyccn_cmd_DER_read_key(PyObject *UNUSED(self), PyObject *args,
		PyObject *py_kwds)
{
	PyObject *py_private_der = Py_None, *py_public_der = Py_None;
	PyObject *py_der;
	PyObject *py_private_key, *py_public_key, *py_digest, *py_ret;
	int digest_len, r;
	int is_public_only = -1, is_file = -1;

	static char *kwlist[] = {"private", "public", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, py_kwds, "|OO", kwlist,
			&py_private_der, &py_public_der))
		return NULL;

	assert(py_private_der);
	assert(py_public_der);

	if (py_private_der != Py_None) {
		py_der = py_private_der;
		is_public_only = 0;
		is_file = 0;
		goto do_work;
	} else if (py_public_der != Py_None) {
		py_der = py_public_der;
		is_public_only = 1;
		is_file = 0;
		goto do_work;
	}

	PyErr_SetString(PyExc_ValueError, "expected value with one of the"
			" arguments: private, public, private_file, public_file");
	return NULL;

do_work:
	assert(is_public_only == 0 || is_public_only == 1);
	assert(is_file == 0 || is_file == 1);

	if (!is_file) {
		if (!PyBytes_Check(py_der)) {
			PyErr_SetString(PyExc_TypeError, "expected bytes type");
			return NULL;
		}

		r = put_key_der(is_public_only, py_der, &py_private_key, &py_public_key,
				&py_digest, &digest_len);
	}
	if (r < 0)
		return NULL;

	py_ret = Py_BuildValue("(OOO)", py_private_key, py_public_key, py_digest);
	Py_DECREF(py_private_key);
	Py_DECREF(py_public_key);
	Py_DECREF(py_digest);

	return py_ret;
}

PyObject *
_pyccn_cmd_DER_write_key(PyObject *UNUSED(self), PyObject *args,
		PyObject *py_kwds)
{
	PyObject *py_pkey;
	struct ccn_pkey *pkey;
	PyObject *py_file = Py_None;
	int isprivate = -1;

	static char *kwlist[] = {"key", "file", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, py_kwds, "O|O", kwlist, &py_pkey,
			&py_file))
		return NULL;

	if (CCNObject_IsValid(PKEY_PRIV, py_pkey)) {
		isprivate = 1;
		pkey = CCNObject_Get(PKEY_PRIV, py_pkey);
	} else if (CCNObject_IsValid(PKEY_PUB, py_pkey)) {
		isprivate = 0;
		pkey = CCNObject_Get(PKEY_PUB, py_pkey);
	} else {
		PyErr_SetString(PyExc_TypeError, "Argument needs to be a CCN PKEY");
		return NULL;
	}

	assert(isprivate >= 0 && isprivate <= 1);
	assert(py_file);

	if (py_file != Py_None) {
		PyErr_SetNone(PyExc_NotImplementedError);
		return NULL;
	} else {
		if (isprivate)
			return get_key_der_private(pkey);
		return get_key_der_public(pkey);
	}

	Py_RETURN_NONE;
}
