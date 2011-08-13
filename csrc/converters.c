#include <Python.h>
#include <ccn/ccn.h>
#include <ccn/hashtb.h>
#include <ccn/signing.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <stdlib.h>

#include "pyccn.h"
#include "converters.h"
#include "key_utils.h"
#include "methods_contentobject.h"
#include "methods_name.h"
#include "misc.h"
#include "objects.h"

// IMPLEMENTATION OF OBJECT CONVERTERS,
// TO AND FROM CCNx LIBRARY STRUCTURES OR
// FROM THE WIRE FORMAT, IF THERE ARE NO
// CORRESPONDING C STRUCTS.


// ************
// Key
//
//

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

// ************
// KeyLocator
//
//

// Can be called directly from c library
//
//	Certificate is not supported yet, as it doesn't seem to be in CCNx.
//

PyObject *
KeyLocator_from_ccn(struct ccn_charbuf* key_locator)
{

	// This accepts a pointer to a charbuf that begins with the DTAG_KeyLocator
	//
	fprintf(stderr, "KeyLocator_from_ccn start\n");

	// 1) Create python object
	PyObject* py_keylocator = PyObject_CallObject(g_type_KeyLocator, NULL);

	// 2) Parse c structure and fill python attributes

	// Based on ccn_locate_key in ccn_client
	int res = 0;
	struct ccn_buf_decoder decoder;
	struct ccn_buf_decoder *d;
	struct ccn_pkey *pubkey;
	size_t start;
	size_t stop;

	d = ccn_buf_decoder_start(&decoder, key_locator->buf, key_locator->length);

	// TODO: Rewrite to simplify
	if (ccn_buf_match_dtag(d, CCN_DTAG_KeyLocator)) {
		ccn_buf_advance(d);
		if (ccn_buf_match_dtag(d, CCN_DTAG_KeyName)) {
			ccn_buf_advance(d);
			start = d->decoder.token_index;
			if (!ccn_buf_match_dtag(d, CCN_DTAG_Name)) {
				fprintf(stderr, "No name inside? \n");
			} else {
				ccn_buf_advance(d);
			}
			// TODO: srsly?   Matching a blob doesn't seem to work, so we have to iterate through
			// couldn't there be a... ignore internal tags?
			while (ccn_buf_match_dtag(d, CCN_DTAG_Component)) {
				ccn_buf_advance(d);
				if (ccn_buf_match_blob(d, NULL, NULL)) {
					ccn_buf_advance(d);
				}
				ccn_buf_check_close(d);
			}
			stop = d->decoder.token_index;
			if (stop > start) {
				fprintf(stderr, "Parse CCN_DTAG_Name inside KeyName, len=%zd\n", stop - start);
				PyObject* py_name = Name_from_ccn_tagged_bytearray(d->buf + start, stop - start);
				Py_INCREF(py_name);
				PyObject_SetAttrString(py_keylocator, "name", py_name);
			} else {
				fprintf(stderr, "Error parsing CCN_DTAG_KeyName, res = %d\n", res);
			}
		} else if (ccn_buf_match_dtag(d, CCN_DTAG_Key)) {
			const unsigned char *dkey;
			size_t dkey_size;
			start = d->decoder.token_index;
			ccn_parse_required_tagged_BLOB(d, CCN_DTAG_Key, 1, -1);
			stop = d->decoder.token_index;
			res = ccn_ref_tagged_BLOB(CCN_DTAG_Key, d->buf,
					start, stop,
					&dkey, &dkey_size);
			if (res == 0) {
				fprintf(stderr, "Parse CCN_DTAG_Key, len=%zd\n", dkey_size);
				pubkey = ccn_d2i_pubkey(dkey, dkey_size); // free with ccn_pubkey_free()
				PyObject* py_key = Key_from_ccn(pubkey); // Now the key object must destroy it.s
				Py_INCREF(py_key);
				PyObject_SetAttrString(py_keylocator, "key", py_key);
			} else {
				fprintf(stderr, "Error parsing CCN_DTAG_Key, res = %d\n", res);
			}
		} else if (ccn_buf_match_dtag(d, CCN_DTAG_Certificate)) {
			fprintf(stderr, "KeyLocator_from_ccn certificate DTAG found?? Unsupported.\n");
		}

		ccn_buf_check_close(d); // we don't really check the parser, though-
	} else {
		fprintf(stderr, "Parse result for Keylocator DTAG: %d\n", res);

	}
	if (res != 0) {
		py_keylocator = Py_None;
		Py_INCREF(py_keylocator);
		return py_keylocator;
	}
	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	PyObject* ccn_data = CCNObject_New(KEY_LOCATOR, key_locator);
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_keylocator, "ccn_data", ccn_data);

	// 4) Return the created object
	fprintf(stderr, "KeyLocator_from_ccn ends\n");
	return py_keylocator;
}



// ************
// ExclusionFilter
//
//

void
__ccn_exclusion_filter_destroy(void* p)
{
	if (p != NULL)
		;
}

struct ccn_charbuf*
ExclusionFilter_to_ccn(PyObject* py_ExclusionFilter)
{
	struct ccn_charbuf* exclude = ccn_charbuf_create();
	//  Build exclusion list - This uses explicit exclusion rather than Bloom filters
	//  as Bloom will be deprecated
	//  IMPORTANT:  Exclusion component list must be sorted following "Canonical CCNx ordering"
	//              http://www.ccnx.org/releases/latest/doc/technical/CanonicalOrder.html
	// 				in which shortest components go first.
	// This sorting is expected to be handled on the Python side, not here.
	//
	if (py_ExclusionFilter == Py_None)
		return exclude;

	ccn_charbuf_append_tt(exclude, CCN_DTAG_Exclude, CCN_DTAG);

	// This code is similar to what's used in Name;
	// could probably be generalized.

	PyObject *iterator = PyObject_GetIter(py_ExclusionFilter);
	PyObject *item;
	if (iterator == NULL) {
		// TODO: Return error
	}
	Py_ssize_t blobsize;
	const char* blob;
	while ((item = PyIter_Next(iterator))) {
		if (PyByteArray_Check(item)) {
			blobsize = PyByteArray_Size(item);
			blob = PyByteArray_AsString(item);
		} else if (PyString_Check(item)) { // Unicode or UTF-8?
			blob = PyString_AsString(item);
			blobsize = strlen(blob); // more efficient way?
			// Note, we choose to convert numbers to their string
			// representation; if we want numeric encoding, use a
			// byte array and do it explicitly.
		} else if (PyFloat_Check(item) || PyLong_Check(item)
				|| PyInt_Check(item)) {
			PyObject* p = PyObject_Str(item);
			blob = PyString_AsString(p);
			blobsize = strlen(blob); // More efficient way?
		} else {
			// TODO: Throw error
			fprintf(stderr, "Can't encoded component, type unknown.\n");
		}
		Py_DECREF(item); // do we do this here?
		ccnb_append_tagged_blob(exclude, CCN_DTAG_Component, blob, blobsize);
	}
	Py_DECREF(iterator);
	if (PyErr_Occurred()) {
		// TODO: Propagate error
	}
	ccn_charbuf_append_closer(exclude); /* </Exclude> */
	return exclude;
}


// Can be called directly from c library

PyObject*
ExclusionFilter_from_ccn(struct ccn_charbuf* ExclusionFilter)
{
	fprintf(stderr, "ExclusionFilter_from_ccn start\n");

	// 1) Create python object
	PyObject* py_exclusionfilter = PyObject_CallObject(g_type_ExclusionFilter, NULL);

	// 2) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString
	//
	//    self.data = None        # shoudl this be a list?
	//    # pyccn
	//    self.ccn_data_dirty = False
	//    self.ccn_data = None  # backing charbuf

	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	PyObject* ccn_data = PyCObject_FromVoidPtr((void*) ExclusionFilter, __ccn_exclusion_filter_destroy);
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_exclusionfilter, "ccn_data", ccn_data);

	// 4) Return the created object
	fprintf(stderr, "ExclusionFilter_from_ccn ends\n");
	return py_exclusionfilter;
}
// From within python
//
//TODO: Check cobjecttype



// ************
// Interest
//
//

void
__ccn_interest_destroy(void* p)
{
	if (p != NULL)
		ccn_charbuf_destroy((struct ccn_charbuf**) &p);
}

void
__ccn_parsed_interest_destroy(void* p)
{
	if (p != NULL)
		free(p);
}

struct ccn_charbuf*
Interest_to_ccn(PyObject* py_interest)
{
	struct ccn_charbuf* interest;

	PyObject* p;

	interest = ccn_charbuf_create();

	ccn_charbuf_append_tt(interest, CCN_DTAG_Interest, CCN_DTAG);


	if ((p = PyObject_GetAttrString(py_interest, "name")) != Py_None) {
		struct ccn_charbuf* name = Name_to_ccn(p);
		ccn_charbuf_append_charbuf(interest, name);
		ccn_charbuf_destroy(&name);
	} else { // Empty name because it is required?
		ccn_charbuf_append_tt(interest, CCN_DTAG_Name, CCN_DTAG);
		ccn_charbuf_append_closer(interest); /* </Name> */
	}


	if ((p = PyObject_GetAttrString(py_interest, "minSuffixComponents")) != Py_None) {
		ccnb_tagged_putf(interest, CCN_DTAG_MinSuffixComponents, "%dl", PyInt_AsLong(p));
	}
	if ((p = PyObject_GetAttrString(py_interest, "maxSuffixComponents")) != Py_None) {
		ccnb_tagged_putf(interest, CCN_DTAG_MaxSuffixComponents, "%dl", PyInt_AsLong(p));
	}
	if ((p = PyObject_GetAttrString(py_interest, "publisherPublicKeyDigest")) != Py_None) { // expect a byte array?
		// TODO: Type check here?
		size_t blobsize = (size_t) PyByteArray_Size(p);
		const char* blob = PyByteArray_AsString(p);
		ccnb_append_tagged_blob(interest, CCN_DTAG_PublisherPublicKeyDigest, blob, blobsize);
	}
	if ((p = PyObject_GetAttrString(py_interest, "exclude")) != Py_None) {
		struct ccn_charbuf* exclusionfilter = ExclusionFilter_to_ccn(p);
		ccn_charbuf_append_charbuf(interest, exclusionfilter);
		ccn_charbuf_destroy(&exclusionfilter);
	}
	if ((p = PyObject_GetAttrString(py_interest, "childSelector")) != Py_None) {
		ccnb_tagged_putf(interest, CCN_DTAG_ChildSelector, "%dl", PyInt_AsLong(p));
	}
	if ((p = PyObject_GetAttrString(py_interest, "answerOriginKind")) != Py_None) {
		ccnb_tagged_putf(interest, CCN_DTAG_AnswerOriginKind, "%dl", PyInt_AsLong(p));
	}
	if ((p = PyObject_GetAttrString(py_interest, "scope")) != Py_None) {
		ccnb_tagged_putf(interest, CCN_DTAG_Scope, "%dl", PyInt_AsLong(p));
	}
	if ((p = PyObject_GetAttrString(py_interest, "interestLifetime")) != Py_None) {
		ccnb_tagged_putf(interest, CCN_DTAG_InterestLifetime, "%dl", PyLong_AsLong(p));
	}
	if ((p = PyObject_GetAttrString(py_interest, "nonce")) != Py_None) {
		// TODO: Nonce
		// This is automatically added by the library?
		//
	}

	ccn_charbuf_append_closer(interest); /* </Interest> */

	return interest;
}

// Can be called directly from c library

PyObject*
Interest_from_ccn_parsed(struct ccn_charbuf* interest, struct ccn_parsed_interest* pi)
{
	fprintf(stderr, "KeyLocator_from_ccn start\n");

	// 1) Create python object
	PyObject* py_interest = PyObject_CallObject(g_type_Interest, NULL);

	// 2) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString

	ssize_t l;
	const unsigned char *blob;
	size_t blob_size;
	PyObject* p;
	struct ccn_charbuf* cb;
	int i;

	// Best decoding examples are in packet-ccn.c for wireshark plugin?

	//        self.name = None  # Start from None to use for templates?
	l = CCN_PI_E_Name - CCN_PI_B_Name;
	if (l > 0) {
		PyObject *py_cname;
		py_cname = CCNObject_New_charbuf(NAME, &cb);
		ccn_charbuf_append(cb, interest->buf + pi->offset[CCN_PI_B_Name], l);
		p = Name_from_ccn(py_cname);
		Py_DECREF(py_cname);
		PyObject_SetAttrString(py_interest, "name", p);
		Py_INCREF(p);
	}

	//        self.minSuffixComponents = None  # default 0
	l = CCN_PI_E_MinSuffixComponents - CCN_PI_B_MinSuffixComponents;
	if (l > 0) {
		i = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_MinSuffixComponents, interest->buf,
				pi->offset[CCN_PI_B_MinSuffixComponents], pi->offset[CCN_PI_E_MinSuffixComponents]);
		p = PyInt_FromLong(i);
		PyObject_SetAttrString(py_interest, "minSuffixComponents", p);
		Py_INCREF(p);
	}

	//        self.maxSuffixComponents = None  # default infinity
	l = CCN_PI_E_MaxSuffixComponents - CCN_PI_B_MaxSuffixComponents;
	if (l > 0) {
		i = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_MaxSuffixComponents, interest->buf,
				pi->offset[CCN_PI_B_MaxSuffixComponents], pi->offset[CCN_PI_E_MaxSuffixComponents]);
		p = PyInt_FromLong(i);
		PyObject_SetAttrString(py_interest, "maxSuffixComponents", p);
		Py_INCREF(p);
	}

	//        self.publisherPublicKeyDigest = None   # SHA256 hash
	// TODO: what is CN_PI_B_PublisherID?
	l = CCN_PI_E_PublisherIDKeyDigest - CCN_PI_B_PublisherIDKeyDigest;
	if (l > 0) {
		i = ccn_ref_tagged_BLOB(CCN_DTAG_PublisherPublicKeyDigest, interest->buf,
				pi->offset[CCN_PI_B_PublisherIDKeyDigest],
				pi->offset[CCN_PI_E_PublisherIDKeyDigest],
				&blob, &blob_size);
		p = PyByteArray_FromStringAndSize((const char*) blob, blob_size);
		PyObject_SetAttrString(py_interest, "publisherPublicKeyDigest", p);
		Py_INCREF(p);
	}

	//        self.exclude = None
	l = CCN_PI_E_Exclude - CCN_PI_B_Exclude;
	if (l > 0) {
		cb = ccn_charbuf_create(); // freed by python destructor that holds the pointer
		ccn_charbuf_append(cb, interest->buf + pi->offset[CCN_PI_B_Exclude], l);
		p = ExclusionFilter_from_ccn(cb);
		PyObject_SetAttrString(py_interest, "exclude", p);
		Py_INCREF(p);
	}

	//        self.childSelector = None
	l = CCN_PI_E_ChildSelector - CCN_PI_B_ChildSelector;
	if (l > 0) {
		i = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_ChildSelector, interest->buf,
				pi->offset[CCN_PI_B_ChildSelector], pi->offset[CCN_PI_E_ChildSelector]);
		p = PyInt_FromLong(i);
		PyObject_SetAttrString(py_interest, "childSelector", p);
		Py_INCREF(p);
	}

	//        self.answerOriginKind = None
	l = CCN_PI_E_AnswerOriginKind - CCN_PI_B_AnswerOriginKind;
	if (l > 0) {
		i = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_AnswerOriginKind, interest->buf,
				pi->offset[CCN_PI_B_AnswerOriginKind], pi->offset[CCN_PI_E_AnswerOriginKind]);
		p = PyInt_FromLong(i);
		PyObject_SetAttrString(py_interest, "answerOriginKind", p);
		Py_INCREF(p);
	}

	//        self.scope  = None
	l = CCN_PI_E_Scope - CCN_PI_B_Scope;
	if (l > 0) {
		i = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_Scope, interest->buf,
				pi->offset[CCN_PI_B_Scope], pi->offset[CCN_PI_E_Scope]);
		p = PyInt_FromLong(i);
		PyObject_SetAttrString(py_interest, "scope", p);
		Py_INCREF(p);
	}

	//        self.interestLifetime = None
	l = CCN_PI_E_InterestLifetime - CCN_PI_B_InterestLifetime;
	if (l > 0) {
		// From packet-ccn.c
		i = ccn_ref_tagged_BLOB(CCN_DTAG_InterestLifetime, interest->buf,
				pi->offset[CCN_PI_B_InterestLifetime],
				pi->offset[CCN_PI_E_InterestLifetime],
				&blob, &blob_size);
		double lifetime = 0.0;
		for (i = 0; i < blob_size; i++)
			lifetime = lifetime * 256.0 + (double) blob[i];
		lifetime /= 4096.0;
		p = PyFloat_FromDouble(lifetime);
		PyObject_SetAttrString(py_interest, "interestLifetime", p);
		Py_INCREF(p);
	}

	//        self.nonce = None
	l = CCN_PI_E_Nonce - CCN_PI_B_Nonce;
	if (l > 0) {
		i = ccn_ref_tagged_BLOB(CCN_DTAG_Nonce, interest->buf,
				pi->offset[CCN_PI_B_Nonce],
				pi->offset[CCN_PI_E_Nonce],
				&blob, &blob_size);
		p = PyByteArray_FromStringAndSize((const char*) blob, blob_size);
		PyObject_SetAttrString(py_interest, "nonce", p);
		Py_INCREF(p);
	}

	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	PyObject* ccn_data = PyCObject_FromVoidPtr((void*) interest, __ccn_interest_destroy);
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_interest, "ccn_data", ccn_data);
	PyObject* ccn_data_parsed = PyCObject_FromVoidPtr((void*) pi, __ccn_parsed_interest_destroy);
	Py_INCREF(ccn_data_parsed);
	PyObject_SetAttrString(py_interest, "ccn_data_parsed", ccn_data_parsed);

	// 4) Return the created object
	fprintf(stderr, "Interest_from_ccn ends\n");
	return py_interest;
}

// Can be called directly from c library

PyObject*
Interest_from_ccn(struct ccn_charbuf* interest)
{
	struct ccn_parsed_interest* parsed_interest = calloc(sizeof(struct ccn_parsed_interest), 1);
	int result = 0;
	result = ccn_parse_interest(interest->buf, interest->length, parsed_interest, NULL /* no comps */);
	// TODO: Check result
	return Interest_from_ccn_parsed(interest, parsed_interest);
}






// ************
// SignedInfo
//
//

void
__ccn_signed_info_destroy(void* p)
{
	if (p != NULL)
		ccn_charbuf_destroy((struct ccn_charbuf**) &p);
}

// Can be called directly from c library
//
// Pointer to a tagged blob starting with CCN_DTAG_SignedInfo
//

PyObject*
SignedInfo_from_ccn(struct ccn_charbuf* signed_info)
{
	fprintf(stderr, "SignedInfo_from_ccn start, size=%zd\n", signed_info->length);

	// 1) Create python object
	PyObject* py_signedinfo = PyObject_CallObject(g_type_SignedInfo, NULL);

	// 2) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString
	// based on chk_signing_params
	// from ccn_client.c
	//
	//outputs:

	// Note, it is ok that non-filled optional elements
	// are initialized to None (through the .py file __init__)
	//

	PyObject* p;


	//
	struct ccn_buf_decoder decoder;
	struct ccn_buf_decoder *d;
	size_t start;
	size_t stop;
	size_t size;
	const unsigned char *ptr = NULL;
	int i = 0;
	d = ccn_buf_decoder_start(&decoder,
			signed_info->buf,
			signed_info->length);
	if (ccn_buf_match_dtag(d, CCN_DTAG_SignedInfo)) {
		ccn_buf_advance(d);
		if (ccn_buf_match_dtag(d, CCN_DTAG_PublisherPublicKeyDigest))
			start = d->decoder.token_index;
		//TODO - what if not?
		ccn_parse_required_tagged_BLOB(d, CCN_DTAG_PublisherPublicKeyDigest, 16, 64);
		stop = d->decoder.token_index; // check - do we need this here?
		i = ccn_ref_tagged_BLOB(CCN_DTAG_PublisherPublicKeyDigest, d->buf, start, stop, &ptr, &size);
		if (i == 0) {
			//    self.publisherPublicKeyDigest = None     # SHA256 hash
			fprintf(stderr, "PyObject_SetAttrString publisherPublicKeyDigest\n");
			p = PyByteArray_FromStringAndSize((const char*) ptr, size);
			PyObject_SetAttrString(py_signedinfo, "publisherPublicKeyDigest", p);
			Py_INCREF(p);
		}

		start = d->decoder.token_index;
		ccn_parse_optional_tagged_BLOB(d, CCN_DTAG_Timestamp, 1, -1);
		stop = d->decoder.token_index;
		i = ccn_ref_tagged_BLOB(CCN_DTAG_Timestamp, d->buf, start, stop, &ptr, &size);
		if (i == 0) {
			//    self.timeStamp = None   # CCNx timestamp
			fprintf(stderr, "PyObject_SetAttrString timestamp\n");
			p = PyByteArray_FromStringAndSize((const char*) ptr, size);
			PyObject_SetAttrString(py_signedinfo, "timestamp", p);
			Py_INCREF(p);
		}
		start = d->decoder.token_index;
		ccn_parse_optional_tagged_BLOB(d, CCN_DTAG_Type, 1, -1);
		stop = d->decoder.token_index;
		i = ccn_ref_tagged_BLOB(CCN_DTAG_Type, d->buf, start, stop, &ptr, &size);
		if (i == 0) {
			//    type = None   # CCNx type
			// TODO: Provide a string representation with the Base64 mnemonic?
			fprintf(stderr, "PyObject_SetAttrString type\n");
			p = PyByteArray_FromStringAndSize((const char*) ptr, size);
			PyObject_SetAttrString(py_signedinfo, "type", p);
			Py_INCREF(p);
		}
		i = ccn_parse_optional_tagged_nonNegativeInteger(d, CCN_DTAG_FreshnessSeconds);
		if (i >= 0) {
			//    self.freshnessSeconds = None
			fprintf(stderr, "PyObject_SetAttrString freshnessSeconds\n");
			p = PyLong_FromLong(i);
			PyObject_SetAttrString(py_signedinfo, "freshnessSeconds", p);
			Py_INCREF(p);
		}
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
				p = PyByteArray_FromStringAndSize((const char*) (d->buf + start), stop - start);
				PyObject_SetAttrString(py_signedinfo, "finalBlockID", p);
				Py_INCREF(p);
			}
		}
		start = d->decoder.token_index;
		if (ccn_buf_match_dtag(d, CCN_DTAG_KeyLocator))
			ccn_buf_advance_past_element(d);
		stop = d->decoder.token_index;
		if (d->decoder.state >= 0 && stop > start) {
			fprintf(stderr, "PyObject_SetAttrString keyLocator, len=%zd\n", stop - start);
			struct ccn_charbuf* keyLocator = ccn_charbuf_create();
			ccn_charbuf_append(keyLocator, d->buf + start, stop - start);
			//    self.keyLocator = None
			p = KeyLocator_from_ccn(keyLocator); // it will free
			PyObject_SetAttrString(py_signedinfo, "keyLocator", p);
			Py_INCREF(p);
		}
		ccn_buf_check_close(d);
	} else {
		fprintf(stderr, "Did not pass data starting with CCN_DTAG_SignedInfo.\n");
	}
	if (d->decoder.state < 0) {
		fprintf(stderr, "SignedInfo decode error.\n");
	}

	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	PyObject* ccn_data = PyCObject_FromVoidPtr((void*) signed_info, __ccn_signed_info_destroy);
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_signedinfo, "ccn_data", ccn_data);

	// 4) Return the created object
	fprintf(stderr, "SignedInfo_from_ccn ends\n");
	return py_signedinfo;
}



// ************
// SigningParams
//
//

// Note that SigningParams information is essentially redundant
// to what's in SignedInfo, and is internal to the
// ccn libraries.
// See the source for ccn_sign_content, for example.
//
// To use it requires working with keystores & hashtables to
// reference keys, which requires accessing private functions in the library
//
// So, we don't provide "to_ccn" functionality here, only "from_ccn" in case
// there is a need to parse a struct coming from the c library.


// Can be called directly from c library
//
// Pointer to a struct ccn_signing_params
//

static void
__ccn_signing_params_destroy(void* p)
{
	if (p != NULL) {
		struct ccn_signing_params* sp = (struct ccn_signing_params*) p;
		if (sp->template_ccnb != NULL)
			ccn_charbuf_destroy(&sp->template_ccnb);
		free(p);
	}
}

PyObject*
SigningParams_from_ccn(struct ccn_signing_params* signing_params)
{
	fprintf(stderr, "SigningParams_from_ccn start\n");

	// 1) Create python object
	PyObject* py_SigningParams = PyObject_CallObject(g_type_SigningParams, NULL);

	// 2) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString
	PyObject* p;

	p = PyInt_FromLong(signing_params->sp_flags);
	PyObject_SetAttrString(py_SigningParams, "flags", p);
	Py_INCREF(p);

	p = PyInt_FromLong(signing_params->type);
	PyObject_SetAttrString(py_SigningParams, "type", p);
	Py_INCREF(p);

	p = PyInt_FromLong(signing_params->freshness);
	PyObject_SetAttrString(py_SigningParams, "freshness", p);
	Py_INCREF(p);

	p = PyInt_FromLong(signing_params->api_version);
	PyObject_SetAttrString(py_SigningParams, "apiVersion", p);
	Py_INCREF(p);

	if (signing_params->template_ccnb != NULL)
		if (signing_params->template_ccnb->length > 0)
			p = SignedInfo_from_ccn(signing_params->template_ccnb);
		else
			p = Py_None;
	else
		p = Py_None;
	PyObject_SetAttrString(py_SigningParams, "template", p);
	Py_INCREF(p);

	// Right now we're going to set this to the byte array corresponding
	// to the key hash, but this is not ideal
	// TODO:  Figure out how to deal with keys here...
	p = PyByteArray_FromStringAndSize((char*) signing_params->pubid, 32);
	PyObject_SetAttrString(py_SigningParams, "key", p);
	Py_INCREF(p);

	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	PyObject* ccn_data = PyCObject_FromVoidPtr((void*) signing_params, __ccn_signing_params_destroy);
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_SigningParams, "ccn_data", ccn_data);

	// 4) Return the created object
	fprintf(stderr, "SigningParams_from_ccn ends\n");
	return py_SigningParams;
}



// ************
// UpcallInfo
//
//

// Can be called directly from c library

PyObject *
UpcallInfo_from_ccn(struct ccn_upcall_info *ui)
{
	PyObject *py_upcall_info;
	PyObject *py_o;
	PyObject *py_data = NULL, *py_pco = NULL, *py_comps = NULL;
	struct ccn_charbuf *data;
	struct ccn_parsed_ContentObject *pco;
	struct ccn_indexbuf *comps;
	int r;

	//TODO: fix this
	if (!ui->content_ccnb)
		Py_RETURN_NONE;

	assert(ui->content_ccnb);

	// Create name object
	assert(g_type_UpcallInfo);
	py_upcall_info = PyObject_CallObject(g_type_UpcallInfo, NULL);
	JUMP_IF_NULL(py_upcall_info, error);

	// CCN handle (I hope it isn't freed)
	py_o = CCNObject_Borrow(HANDLE, ui->h);
	r = PyObject_SetAttrString(py_upcall_info, "ccn", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	py_data = CCNObject_New_charbuf(CONTENT_OBJECT, &data);
	JUMP_IF_NULL(py_data, error);
	r = ccn_charbuf_append(data, ui->content_ccnb, ui->pco->offset[CCN_PCO_E]);
	JUMP_IF_NEG_MEM(r, error);

	py_pco = CCNObject_New_ParsedContentObject(&pco);
	JUMP_IF_NULL(py_pco, error);

	py_comps = CCNObject_New_ContentObjectComponents(&comps);
	JUMP_IF_NULL(py_comps, error);

	py_o = ContentObject_from_ccn_parsed(py_data, py_pco, py_comps);
	Py_CLEAR(py_comps);
	Py_CLEAR(py_pco);
	Py_CLEAR(py_data);
	JUMP_IF_NULL(py_o, error);

	r = PyObject_SetAttrString(py_upcall_info, "ContentObject", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	return py_upcall_info;

error:
	Py_XDECREF(py_comps);
	Py_XDECREF(py_pco);
	Py_XDECREF(py_data);
	Py_XDECREF(py_upcall_info);
	return NULL;
}


// ************
// ContentObject
//
//


