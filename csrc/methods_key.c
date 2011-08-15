#include <Python.h>
#include <ccn/ccn.h>
#include <ccn/signing.h>
#include <openssl/evp.h>

#include "pyccn.h"
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

	r = ccnb_append_tagged_blob(keylocator, CCN_DTAG_Name, name->buf, name->length); // check
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

	if (!CCNObject_IsValid(PKEY, py_key)) {
		PyErr_SetString(PyExc_TypeError, "Argument needs to be of type CCN Key");
		return -1;
	}

	key = CCNObject_Get(PKEY, py_key);

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
	key = CCNObject_Get(PKEY, capsule);
	Py_DECREF(capsule);

	return key;
}

// Can be called directly from c library
// Note that this isn't the wire format, so we
// do a potentially redundant step here and regenerate the DER format
// so that we can do the key hash

PyObject *
Key_from_ccn(struct ccn_pkey* key_ccn)
{
	fprintf(stderr, "Key_from_ccn start\n");

	assert(g_type_Key);

	// 1) Create python object
	PyObject* py_key = PyObject_CallObject(g_type_Key, NULL);

	// 2) Parse c structure and fill python attributes

	// If this is a private key, split private and public keys
	// There is probably a less convoluted way to do this than pulling it out to RSA
	// Also, create the digest...
	// These non-ccn functions assume the CCN defaults, RSA + SHA256
	RSA* private_key_rsa = EVP_PKEY_get1_RSA((EVP_PKEY*) key_ccn);
	struct ccn_pkey *private_key_ccn, *public_key_ccn;
	unsigned char* public_key_digest;
	size_t public_key_digest_len;
	ccn_keypair_from_rsa(private_key_rsa, &private_key_ccn, &public_key_ccn);
	create_public_key_digest(private_key_rsa, &public_key_digest, &public_key_digest_len);
	//  ccn_digest has a more convoluted API, with examples
	// in ccn_client, but *for now* it boils down to the same thing.

	PyObject* p;


	// type
	p = PyString_FromString("RSA");
	PyObject_SetAttrString(py_key, "type", p);
	Py_INCREF(p);


	// publicKeyID
	p = PyByteArray_FromStringAndSize((char*) public_key_digest, public_key_digest_len);
	PyObject_SetAttrString(py_key, "publicKeyID", p);
	Py_INCREF(p);
	//free (public_key_digest); -- this is the job of python
	// publicKeyIDsize
	p = PyInt_FromLong(public_key_digest_len);
	PyObject_SetAttrString(py_key, "publicKeyIDsize", p);
	Py_INCREF(p);

	// pubID
	// TODO: pubID not implemented
	p = Py_None;
	PyObject_SetAttrString(py_key, "pubID", p);
	Py_INCREF(p);

	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	// privateKey
	// Don't free these here, python will call destructor
	p = CCNObject_New(PKEY, private_key_ccn);
	PyObject_SetAttrString(py_key, "ccn_data_private", p);
	Py_INCREF(p);

	// publicKey
	// Don't free this here, python will call destructor
	p = CCNObject_New(PKEY, public_key_ccn);
	PyObject_SetAttrString(py_key, "ccn_data_public", p);
	Py_DECREF(p);

	// 4) Return the created object

	//free(public_key_digest);

	fprintf(stderr, "Key_from_ccn ends\n");
	return py_key;
}

// Can be called directly from c library
//
//	Certificate is not supported yet, as it doesn't seem to be in CCNx.
//

PyObject *
KeyLocator_from_ccn(PyObject *py_keylocator)
{
	struct ccn_buf_decoder decoder, *d;
	struct ccn_charbuf *keylocator;
	struct ccn_charbuf *name;
	struct ccn_pkey *pubkey;
	size_t start, stop;
	int r;
	PyObject *py_res;

	keylocator = CCNObject_Get(KEY_LOCATOR, py_keylocator);

	debug("KeyLocator_from_ccn start\n");

	d = ccn_buf_decoder_start(&decoder, keylocator->buf, keylocator->length);
	assert(d); //should always succeed

	if (!ccn_buf_match_dtag(d, CCN_DTAG_KeyLocator)) {
		PyErr_SetString(g_PyExc_CCNError, "The input isn't a valid KeyLocator");
		return NULL;
	}
	ccn_buf_advance(d);

	if (ccn_buf_match_dtag(d, CCN_DTAG_KeyName)) {
		const unsigned char *bname;
		size_t bname_size;

		ccn_buf_advance(d);

		start = d->decoder.token_index;
		r = ccn_parse_required_tagged_BLOB(d, CCN_DTAG_Name, 1, -1);
		stop = d->decoder.token_index;
		if (r < 0)
			return PyErr_Format(g_PyExc_CCNKeyLocatorError, "Error finding"
				" CCN_DTAG_Name for KeyName (decoder state: %d)",
				d->decoder.state);

		r = ccn_ref_tagged_BLOB(CCN_DTAG_Name, d->buf, start, stop, &bname,
				&bname_size);
		if (r < 0)
			return PyErr_Format(g_PyExc_CCNKeyLocatorError, "Error getting"
				" CCN_DTAG_Name BLOB for KeyName (decoder state: %d)",
				d->decoder.state);

		debug("Parse CCN_DTAG_Name inside KeyName, len=%zd\n", bname_size);

		py_res = CCNObject_New_charbuf(NAME, &name);
		if (!py_res)
			return NULL;

		r = ccn_charbuf_append(name, bname, bname_size);
		if (r < 0) {
			Py_DECREF(py_res);
			return PyErr_NoMemory();
		}
	} else if (ccn_buf_match_dtag(d, CCN_DTAG_Key)) {
		const unsigned char *dkey;
		size_t dkey_size;

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
		py_res = Key_from_ccn(pubkey); // Now the key object must destroy it.s
		ccn_pubkey_free(pubkey);
		if (!py_res)
			return NULL;
	} else if (ccn_buf_match_dtag(d, CCN_DTAG_Certificate)) {
		PyErr_SetString(PyExc_NotImplementedError, "Found certificate DTAG,"
				" which currently is unsupported");
		return NULL;
	} else {
		PyErr_SetString(g_PyExc_CCNKeyLocatorError, "Unknown KeyLocator Type");
		return NULL;
	}

	ccn_buf_check_close(d); // we don't really check the parser, though-

	return py_res;
}

/*
 * From within python
 */

PyObject *
_pyccn_Key_to_ccn_public(PyObject *self, PyObject *py_key)
{
	if (strcmp(py_key->ob_type->tp_name, "Key") != 0) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Key");

		return NULL;
	}

	return PyObject_GetAttrString(py_key, "ccn_data_public");
}

PyObject *
_pyccn_Key_to_ccn_private(PyObject *self, PyObject *py_key)
{
	if (strcmp(py_key->ob_type->tp_name, "Key") != 0) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Key");

		return NULL;
	}

	return PyObject_GetAttrString(py_key, "ccn_data_private");
}

PyObject *
_pyccn_Key_from_ccn(PyObject *self, PyObject *cobj_key)
{
	if (!CCNObject_IsValid(PKEY, cobj_key)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN PKEY object");

		return NULL;
	}

	return Key_from_ccn(CCNObject_Get(PKEY, cobj_key));
}

PyObject *
_pyccn_KeyLocator_to_ccn(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"name", "key", "cert", NULL};
	PyObject *py_name = Py_None, *py_key = Py_None, *py_cert = Py_None;
	struct ccn_charbuf *keylocator;
	int r;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOO", kwlist, &py_name,
			&py_key, &py_cert))
		return NULL;

	keylocator = ccn_charbuf_create();
	JUMP_IF_NULL_MEM(keylocator, error);

	r = ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyLocator, CCN_DTAG);
	JUMP_IF_NEG_MEM(r, error);

	if (py_name != Py_None) {
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

		PyErr_SetString(PyExc_NotImplementedError, "Certificate key locator is not"
				" implemented");
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
_pyccn_KeyLocator_from_ccn(PyObject *self, PyObject *py_keylocator)
{
	if (!CCNObject_IsValid(KEY_LOCATOR, py_keylocator)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Key Locator object");

		return NULL;
	}

	return KeyLocator_from_ccn(py_keylocator);
}
