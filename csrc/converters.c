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
#include "misc.h"
#include "objects.h"

// IMPLEMENTATION OF OBJECT CONVERTERS,
// TO AND FROM CCNx LIBRARY STRUCTURES OR
// FROM THE WIRE FORMAT, IF THERE ARE NO
// CORRESPONDING C STRUCTS.

// ************
// Name

struct ccn_charbuf *
Name_to_ccn(PyObject *py_name)
{
	struct ccn_charbuf *name;
	PyObject *comps, *iterator, *item = NULL;
	int r;

	comps = PyObject_GetAttrString(py_name, "components");
	if (!comps)
		return NULL;

	iterator = PyObject_GetIter(comps);
	Py_DECREF(comps);
	if (!iterator)
		return NULL;

	name = ccn_charbuf_create();
	JUMP_IF_NULL(name, out_of_mem);

	r = ccn_name_init(name);
	JUMP_IF_NEG(r, out_of_mem);

	// Parse the list of components and
	// convert them to C objects
	//
	while ((item = PyIter_Next(iterator))) {
		if (PyByteArray_Check(item)) {
			Py_ssize_t n = PyByteArray_Size(item);
			char *b = PyByteArray_AsString(item);
			r = ccn_name_append(name, b, n);
			JUMP_IF_NEG(r, out_of_mem);
		} else if (PyString_Check(item)) { // Unicode or UTF-8?
			char *s = PyString_AsString(item);
			JUMP_IF_NULL(s, error);

			r = ccn_name_append_str(name, s);
			JUMP_IF_NEG(r, out_of_mem);

			// Note, we choose to convert numbers to their string
			// representation; if we want numeric encoding, use a
			// byte array and do it explicitly.
		} else if (PyFloat_Check(item) || PyLong_Check(item) || PyInt_Check(item)) {
			PyObject *str = PyObject_Str(item);
			JUMP_IF_NULL(str, error);

			char *s = PyString_AsString(str);
			Py_DECREF(str);
			JUMP_IF_NULL(s, error);

			r = ccn_name_append_str(name, s);
			JUMP_IF_NEG(r, out_of_mem);
		} else {
			PyErr_SetString(PyExc_TypeError, "Unknown value type in the list");
			goto error;
		}
		Py_DECREF(item);
	}
	Py_DECREF(iterator);

	return name;

out_of_mem:
	PyErr_SetNone(PyExc_MemoryError);
error:
	Py_XDECREF(item);
	Py_XDECREF(iterator);
	ccn_charbuf_destroy(&name);
	return NULL;
}


// Can be called directly from c library
// For now, everything is a bytearray
//

PyObject *
Name_from_ccn(PyObject *ccn_data)
{
	struct ccn_charbuf *name;

	fprintf(stderr, "Name_from_ccn start\n");

	// Create name object
	PyObject* py_name = PyObject_CallObject(g_type_Name, NULL);

	// Create component list
	PyObject* py_component_list = PyList_New(0);
	PyObject_SetAttrString(py_name, "components", py_component_list);

	// Iterate through name components
	// Copy into byte array
	PyObject* py_component;

	struct ccn_indexbuf* comps = ccn_indexbuf_create();
	name = CCNObject_Get(NAME, ccn_data);
	ccn_name_split(name, comps);

	unsigned char* comp;
	int size;
	int n; // component
	int h; // header size
	for (n = 0; n < comps->n - 1; n++) { // not the implicit digest component
		fprintf(stderr, "Name_from_ccn component %d of %d \n", n, n < comps->n - 1);
		comp = &(name->buf[comps->buf[n]]) + 1; // What is the first byte?  (250?)
		//fprintf(stderr,"\t%s\n", comp);
		for (h = 2; h < (comps->buf[n + 1] - comps->buf[n]); h++) { // walk through the header until the terminators is found
			if (*(comp++) > 127) break;
		}
		size = (int) (comps->buf[n + 1] - comps->buf[n]) - 1 - h; // don't include the DTAG Component
		py_component = PyByteArray_FromStringAndSize((char*) comp, size);
		PyList_Append(py_component_list, py_component);
		Py_DECREF(py_component);
	}
	// TODO: Add implicit digest componet?
	// TODO: Parse version & segment?

	PyObject_SetAttrString(py_name, "ccn_data", ccn_data);

	ccn_indexbuf_destroy(&comps);

	fprintf(stderr, "Name_from_ccn ends\n");
	return py_name;
}

// Takes a byte array with DTAG
//

PyObject *
Name_from_ccn_tagged_bytearray(const unsigned char *buf, size_t size)
{
	PyObject *py_name, *py_cname;
	struct ccn_charbuf *name;
	int r;

	name = ccn_charbuf_create();
	if (!name)
		return PyErr_NoMemory();

	py_cname = CCNObject_New(NAME, name);
	if (!py_cname) {
		ccn_charbuf_destroy(&name);
		return NULL;
	}

	r = ccn_charbuf_append(name, buf, size);
	py_name = r < 0 ? PyErr_NoMemory() : Name_from_ccn(py_cname);
	Py_DECREF(py_cname);

	return py_name;
}


// ************
// Key
//
//

void
__ccn_key_destroy(void* p)
{
	if (p != NULL)
		ccn_pubkey_free(p); // what about private keys?
}

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

struct ccn_pkey*
Key_to_ccn_public(PyObject* py_key)
{
	// TODO: need to INCREF here?
	return(struct ccn_pkey*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_key, "ccn_data_public"));
}

// Can be called directly from c library
// Note that this isn't the wire format, so we
// do a potentially redundant step here and regenerate the DER format
// so that we can do the key hash

PyObject *
Key_from_ccn(struct ccn_pkey* key_ccn)
{
	fprintf(stderr, "Key_from_ccn start\n");

	assert(g_type_Key != NULL);

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
	p = PyCObject_FromVoidPtr(private_key_ccn, __ccn_key_destroy);
	PyObject_SetAttrString(py_key, "ccn_data_private", p);
	Py_INCREF(p);

	// publicKey
	// Don't free this here, python will call destructor
	p = PyCObject_FromVoidPtr(public_key_ccn, __ccn_key_destroy);
	PyObject_SetAttrString(py_key, "ccn_data_public", p);
	Py_INCREF(p);

	// 4) Return the created object

	//free(public_key_digest);

	fprintf(stderr, "Key_from_ccn ends\n");
	return py_key;
}

// ************
// KeyLocator
//
//

void
__ccn_key_locator_destroy(void* p)
{
	if (p != NULL)
		ccn_charbuf_destroy((struct ccn_charbuf**) &p);
}

struct ccn_charbuf*
KeyLocator_to_ccn(PyObject* py_key_locator)
{
	PyObject* py_keyName = PyObject_GetAttrString(py_key_locator, "keyName");
	PyObject* py_key = PyObject_GetAttrString(py_key_locator, "key");
	PyObject* py_cert = PyObject_GetAttrString(py_key_locator, "cert");
	int res = -1;
	struct ccn_charbuf *keylocator = ccn_charbuf_create();
	ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyLocator, CCN_DTAG);
	if (py_keyName != Py_None) {
		ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyName, CCN_DTAG);
		struct ccn_charbuf* name = Name_to_ccn(py_keyName);
		ccnb_append_tagged_blob(keylocator, CCN_DTAG_Name, name->buf, name->length); // check
		ccn_charbuf_destroy(&name);
		ccn_charbuf_append_closer(keylocator); /* </KeyName> */
	} else if (py_key != Py_None) {
		ccn_charbuf_append_tt(keylocator, CCN_DTAG_Key, CCN_DTAG);
		struct ccn_pkey* key = Key_to_ccn_public(py_key);
		;
		res = ccn_append_pubkey_blob(keylocator, key);
		free(key);
		ccn_charbuf_append_closer(keylocator); /* </Key> */
	} else if (py_cert != Py_None) {
		ccn_charbuf_append_tt(keylocator, CCN_DTAG_Certificate, CCN_DTAG);
		// TODO: How to handle certificate?  ** Not supported here
		ccn_charbuf_append_closer(keylocator); /* </Certificate> */
	}
	ccn_charbuf_append_closer(keylocator); /* </KeyLocator> */

	return keylocator;
}

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
	PyObject* ccn_data = PyCObject_FromVoidPtr((void*) key_locator, __ccn_key_locator_destroy);
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
		py_cname = CCNObject_New_Name(&cb);
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
// Signature
//
//

void
__ccn_signature_destroy(void* p)
{
	if (p != NULL)
		;
}

struct ccn_charbuf*
Signature_to_ccn(PyObject* py_signature)
{
	fprintf(stderr, "Signature_to_ccn starts \n");
	struct ccn_charbuf* sig = ccn_charbuf_create();
	PyObject* py_digestAlgorithm = PyObject_GetAttrString(py_signature, "digestAlgorithm");
	PyObject* py_witness = PyObject_GetAttrString(py_signature, "witness");
	PyObject* py_signatureBits = PyObject_GetAttrString(py_signature, "signatureBits");
	const char* blob;
	size_t blobsize;
	int res = -1;
	res = ccn_charbuf_append_tt(sig, CCN_DTAG_Signature, CCN_DTAG);
	if (py_digestAlgorithm != Py_None) {
		struct ccn_charbuf* digestAlgorithm = ccn_charbuf_create();
		ccn_charbuf_append_string(digestAlgorithm, PyString_AsString(py_digestAlgorithm));
		res = ccnb_append_tagged_blob(sig, CCN_DTAG_DigestAlgorithm, digestAlgorithm->buf, digestAlgorithm->length);
		ccn_charbuf_destroy(&digestAlgorithm);
	}
	if (py_witness != Py_None) {
		blobsize = (size_t) PyByteArray_Size(py_witness);
		blob = PyByteArray_AsString(py_witness);
		fprintf(stderr, "witness blobsize = %zd\n", blobsize);
		res = ccnb_append_tagged_blob(sig, CCN_DTAG_Witness, blob, blobsize);
	}
	if (py_signatureBits != Py_None) {
		blobsize = (size_t) PyByteArray_Size(py_signatureBits);
		blob = PyByteArray_AsString(py_signatureBits);
		res = ccnb_append_tagged_blob(sig, CCN_DTAG_SignatureBits, blob, blobsize);
	}
	res = ccn_charbuf_append_closer(sig); /* </Signature> */
	return sig;
}
// Can be called directly from c library

PyObject*
Signature_from_ccn(struct ccn_charbuf* signature)
{
	fprintf(stderr, "Signature_from_ccn start, len=%zd\n", signature->length);

	// 1) Create python object
	PyObject* py_signature = PyObject_CallObject(g_type_Signature, NULL);

	// 2) Parse c structure and fill python attributes
	PyObject* p;

	// Neither DigestAlgorithm nor Witness are included in the packet
	// from ccnput, so they are apparently both optional
	//
	struct ccn_buf_decoder decoder;
	struct ccn_buf_decoder *d;
	size_t start;
	size_t stop;
	size_t size;
	const unsigned char *ptr = NULL;
	int i = 0;
	d = ccn_buf_decoder_start(&decoder,
			signature->buf,
			signature->length);
	if (ccn_buf_match_dtag(d, CCN_DTAG_Signature)) {
		fprintf(stderr, "Is a signature\n");
		ccn_buf_advance(d);
		start = d->decoder.token_index;
		ccn_parse_optional_tagged_BLOB(d, CCN_DTAG_DigestAlgorithm, 1, -1);
		stop = d->decoder.token_index;
		i = ccn_ref_tagged_BLOB(CCN_DTAG_DigestAlgorithm, d->buf, start, stop, &ptr, &size);
		if (i == 0) {
			//    self.timeStamp = None   # CCNx timestamp
			fprintf(stderr, "PyObject_SetAttrString digestAlgorithm\n");
			p = PyByteArray_FromStringAndSize((const char*) ptr, size);
			PyObject_SetAttrString(py_signature, "digestAlgorithm", p);
			Py_INCREF(p);
		}


		start = d->decoder.token_index;
		ccn_parse_optional_tagged_BLOB(d, CCN_DTAG_Witness, 1, -1);
		stop = d->decoder.token_index;
		fprintf(stderr, "witness start %zd stop %zd\n", start, stop);
		i = ccn_ref_tagged_BLOB(CCN_DTAG_Witness, d->buf, start, stop, &ptr, &size);
		if (i == 0) {
			// The Witness is represented as a DER-encoded PKCS#1 DigestInfo,
			// which contains an AlgorithmIdentifier (an OID, together with any necessary parameters)
			// and a byte array (OCTET STRING) containing the digest information to be interpreted according to that OID.
			// http://www.ccnx.org/releases/latest/doc/technical/SignatureGeneration.html
			fprintf(stderr, "PyObject_SetAttrString witness\n");
			p = PyByteArray_FromStringAndSize((const char*) ptr, size);
			PyObject_SetAttrString(py_signature, "witness", p);
			Py_INCREF(p);
		}
		start = d->decoder.token_index;
		ccn_parse_required_tagged_BLOB(d, CCN_DTAG_SignatureBits, 1, -1);
		stop = d->decoder.token_index;
		i = ccn_ref_tagged_BLOB(CCN_DTAG_SignatureBits, d->buf, start, stop, &ptr, &size);
		if (i == 0) {
			fprintf(stderr, "PyObject_SetAttrString signatureBits\n");
			p = PyByteArray_FromStringAndSize((const char*) ptr, size);
			PyObject_SetAttrString(py_signature, "signatureBits", p);
			Py_INCREF(p);
		}

		ccn_buf_check_close(d);
	} else {
		fprintf(stderr, "Did not pass data starting with CCN_DTAG_Signature.\n");
	}
	if (d->decoder.state < 0) {
		fprintf(stderr, "Signature decode error.\n");
	}

	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	PyObject* ccn_data = PyCObject_FromVoidPtr((void*) signature, __ccn_signature_destroy);
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_signature, "ccn_data", ccn_data);

	// 4) Return the created object
	fprintf(stderr, "Signature_from_ccn ends\n");
	return py_signature;
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

struct ccn_charbuf*
SignedInfo_to_ccn(PyObject* py_signed_info)
{
	struct ccn_charbuf* si = ccn_charbuf_create();
	int result = -1;
	PyObject* py_publisherPublicKeyDigest = PyObject_GetAttrString(py_signed_info, "publisherPublicKeyDigest");
	size_t publisher_key_id_size;
	const void* publisher_key_id;
	if (py_publisherPublicKeyDigest != Py_None) {
		publisher_key_id_size = (size_t) PyByteArray_Size(py_publisherPublicKeyDigest);
		publisher_key_id = PyByteArray_AsString(py_publisherPublicKeyDigest);
	}

	// TODO: Parse timestamp
	struct ccn_charbuf* timestamp = NULL;

	int type = (int) PyInt_AsLong(PyObject_GetAttrString(py_signed_info, "type"));
	int freshness = (int) PyInt_AsLong(PyObject_GetAttrString(py_signed_info, "freshnessSeconds"));

	// TODO: Parse finalblock id
	struct ccn_charbuf* finalblockid = NULL;

	struct ccn_charbuf* key_locator = NULL;
	PyObject* py_keyLocator = PyObject_GetAttrString(py_signed_info, "keyLocator");
	if (py_keyLocator != Py_None) {
		key_locator = (struct ccn_charbuf*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_keyLocator, "ccn_data"));
	}

	result = ccn_signed_info_create(si, publisher_key_id, publisher_key_id_size,
			timestamp, type, freshness, finalblockid, key_locator);
	fprintf(stderr, "ccn_signed_info_create res=%d\n", result);
	return si;
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

static void
__ccn_upcall_info_destroy(void *p)
{
	return;
	// I don't think we destroy this as it is free by the callback routines int he library...
}
// Can be called directly from c library

PyObject *
UpcallInfo_from_ccn(struct ccn_upcall_info *ui)
{
	PyObject *py_upcall_info, *ccn_data;

	// Create name object
	assert(g_type_UpcallInfo);
	py_upcall_info = PyObject_CallObject(g_type_UpcallInfo, NULL);

	//
	// TODO: Build the python UpcallInfo here
	//

	// Set ccn_data to cobject, INCRef
	// We don't have a destructor here is this object does not exist outside of the callback (for now)
	ccn_data = PyCObject_FromVoidPtr(ui, __ccn_upcall_info_destroy);
	PyObject_SetAttrString(py_upcall_info, "ccn_data", ccn_data);
	Py_DECREF(ccn_data);

	return py_upcall_info;
}


// ************
// ContentObject
//
//

static void
__ccn_parsed_content_object_destroy(void* p)
{
	if (p != NULL)
		free(p);
}

static void
__ccn_content_object_components_destroy(void* p)
{
	if (p != NULL)
		ccn_indexbuf_destroy((struct ccn_indexbuf**) &p);
}

static PyObject *
Name_from_ccn_parsed(struct ccn_charbuf *content_object,
		struct ccn_parsed_ContentObject *parsed_content_object)
{
	PyObject *py_Name;
	size_t namelen;
	int r;

	namelen = parsed_content_object->offset[CCN_PCO_E_Name]
			- parsed_content_object->offset[CCN_PCO_B_Name];

	debug("ContentObject_from_ccn_parsed Name len=%zd\n", namelen);
	if (namelen > 0) {
		struct ccn_charbuf *name;
		size_t name_begin, name_end;
		PyObject *py_ccn_name;

		name = ccn_charbuf_create();
		if (!name)
			return PyErr_NoMemory();

		py_ccn_name = CCNObject_New(NAME, name);
		if (!py_ccn_name) {
			ccn_charbuf_destroy(&name);
			return NULL;
		}

		name_begin = parsed_content_object->offset[CCN_PCO_B_Name];
		name_end = parsed_content_object->offset[CCN_PCO_E_Name];

		r = ccn_charbuf_append(name, &content_object->buf[name_begin],
				name_end - name_begin);
		if (r < 0) {
			Py_DECREF(py_ccn_name);
			return PyErr_NoMemory();
		}

		debug("Name: ");
		dump_charbuf(name, stderr);
		debug("\n");

		py_Name = Name_from_ccn(py_ccn_name);
		Py_DECREF(py_ccn_name);
	} else {
		PyErr_SetString(g_PyExc_CCNNameError, "No name stored (or name is"
				" invalid) in parsed content object");
		return NULL;
	}

	return py_Name;
}

static PyObject *
Content_from_ccn_parsed(struct ccn_charbuf *content_object,
		struct ccn_parsed_ContentObject *parsed_content_object)
{
	const char *value;
	size_t size;
	PyObject *py_content;
	int r;

	debug("ContentObject_from_ccn_parsed Content\n");

	r = ccn_content_get_value(content_object->buf, content_object->length,
			parsed_content_object, (const unsigned char **)&value, &size);
	if (r < 0) {
		PyErr_Format(g_PyExc_CCNNameError, "ccn_content_get_value() returned"
				" %d", r);
		return NULL;
	}

	py_content = PyByteArray_FromStringAndSize(value, size);
	if (!py_content)
		return NULL;

	return py_content;
}

PyObject *
ContentObject_from_ccn_parsed(struct ccn_charbuf *content_object,
		struct ccn_parsed_ContentObject *parsed_content_object,
		struct ccn_indexbuf *components)
{
	PyObject *py_ContentObject, *py_o;
	int r;

	debug("ContentObject_from_ccn_parsed content_object->length=%zd\n",
			content_object->length);

	py_ContentObject = PyObject_CallObject(g_type_ContentObject, NULL);
	if (!py_ContentObject)
		return NULL;

	/* Name */
	py_o = Name_from_ccn_parsed(content_object, parsed_content_object);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_ContentObject, "name", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	/* Content */
	py_o = Content_from_ccn_parsed(content_object, parsed_content_object);
	JUMP_IF_NULL(py_o, error);
	r = PyObject_SetAttrString(py_ContentObject, "content", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	debug("ContentObject_from_ccn_parsed Signature\n");

	struct ccn_charbuf* signature = ccn_charbuf_create();
	ccn_charbuf_append(signature, &content_object->buf[parsed_content_object->offset[CCN_PCO_B_Signature]],
			(size_t) (parsed_content_object->offset[CCN_PCO_E_Signature] - parsed_content_object->offset[CCN_PCO_B_Signature]));

	PyObject* py_signature = Signature_from_ccn(signature); // it will destroy?
	PyObject_SetAttrString(py_ContentObject, "signature", py_signature);
	Py_INCREF(py_signature);

	fprintf(stderr, "ContentObject_from_ccn_parsed SignedInfo\n");

	struct ccn_charbuf* signed_info = ccn_charbuf_create();
	ccn_charbuf_append(signed_info, &content_object->buf[parsed_content_object->offset[CCN_PCO_B_SignedInfo]],
			(size_t) (parsed_content_object->offset[CCN_PCO_E_SignedInfo] - parsed_content_object->offset[CCN_PCO_B_SignedInfo]));

	PyObject* py_signedinfo = SignedInfo_from_ccn(signed_info); // it will destroy?
	PyObject_SetAttrString(py_ContentObject, "signedInfo", py_signedinfo);
	Py_INCREF(py_signedinfo);

	fprintf(stderr, "ContentObject_from_ccn_parsed DigestAlgorithm\n");
	PyObject* py_digestalgorithm = Py_None; // TODO...  Note this seems to default to nothing in the library...?
	PyObject_SetAttrString(py_ContentObject, "digestAlgorithm", py_digestalgorithm);
	Py_INCREF(py_digestalgorithm);

	// Set ccn_data to cobject, INCRef
	fprintf(stderr, "ContentObject_from_ccn_parsed ccn_data\n");
	PyObject *ccn_data = CCNObject_New(CONTENT_OBJECT, content_object);
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_ContentObject, "ccn_data", ccn_data);

	fprintf(stderr, "ContentObject_from_ccn_parsed ccn_data_parsed\n");
	PyObject* ccn_data_parsed = PyCObject_FromVoidPtr((void*) parsed_content_object, __ccn_parsed_content_object_destroy);
	Py_INCREF(ccn_data_parsed);
	PyObject_SetAttrString(py_ContentObject, "ccn_data_parsed", ccn_data_parsed);

	fprintf(stderr, "ContentObject_from_ccn_parsed ccn_data_components\n");
	PyObject* ccn_data_components = PyCObject_FromVoidPtr((void*) components, __ccn_content_object_components_destroy);
	Py_INCREF(ccn_data_components);
	PyObject_SetAttrString(py_ContentObject, "ccn_data_components", ccn_data_components);

	fprintf(stderr, "ContentObject_from_ccn_parsed complete\n");

	return py_ContentObject;

error:
	Py_XDECREF(py_ContentObject);
	return NULL;
}

// Can be called directly from c library

PyObject*
ContentObject_from_ccn(struct ccn_charbuf* content_object)
{
	struct ccn_parsed_ContentObject* parsed_content_object = calloc(sizeof(struct ccn_parsed_ContentObject), 1);
	struct ccn_indexbuf* components = ccn_indexbuf_create();
	ccn_parse_ContentObject(content_object->buf, content_object->length, parsed_content_object, components);
	// TODO: Check result
	PyObject* CO = ContentObject_from_ccn_parsed(content_object, parsed_content_object, components);
	free(parsed_content_object);
	ccn_indexbuf_destroy(&components);
	return CO;
}
