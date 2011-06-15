

#include "Python.h"
#include "ccn/ccn.h"
#include "ccn/uri.h"
#include "ccn/signing.h"
#include "pyccn.h"
#include "key_utils.h"

static PyObject* NameType;
static PyObject* CCNType;
static PyObject* InterestType;
static PyObject* ContentObjectType;
static PyObject* ClosureType;
static PyObject* KeyType;
// plus:
static PyObject* ExclusionFilterType;
static PyObject* KeyLocatorType;
static PyObject* SignatureType;
static PyObject* SignedInfoType;
static PyObject* UpcallInfoType;

static PyObject* NameModule;
static PyObject* CCNModule;
static PyObject* InterestModule;
static PyObject* ContentObjectModule;
static PyObject* ClosureModule;
static PyObject* KeyModule;



void dump_charbuf (struct ccn_charbuf* c, FILE* fp) {
	int i=0;
	for (i=0; i < c->length; i++) {
		if (c->buf[i]<0x20 || c->buf[i]>0x7E)
			fprintf(fp,"\\(%i)", c->buf[i]);
		else
			putc(c->buf[i], fp);
	}
}





// ************
// Name
//
//

void __ccn_name_destroy(void* p) {
	if (p != NULL)
		ccn_charbuf_destroy( (struct ccn_charbuf**) &p );
}

struct ccn_charbuf* Name_to_ccn( PyObject* py_name ) {
	struct ccn_charbuf* name;
	name = ccn_charbuf_create();
	ccn_name_init(name);

	PyObject* comps = PyObject_GetAttrString(py_name, "components");
	PyObject *iterator = PyObject_GetIter(comps);
	PyObject *item;

	if (iterator == NULL) {
	   // TODO: Return error
	}

	while ( (item = PyIter_Next(iterator)) ) {
		if (PyByteArray_Check(item)) {
			Py_ssize_t n = PyByteArray_Size(item);
			char* b = PyByteArray_AsString(item);
			ccn_name_append(name, b, n);
		} else if (PyString_Check(item)) {		// Unicode or UTF-8?
			ccn_name_append_str(name, PyString_AsString(item));
		// Note, we choose to convert numbers to their string
		// representation; if we want numeric encoding, use a
		// byte array and do it explicitly.
		} else if (PyFloat_Check(item) || PyLong_Check(item) || PyInt_Check(item)) {
			PyObject* s = PyObject_Str(item);
			ccn_name_append_str(name, PyString_AsString(s));
			Py_DECREF(s);
		} else {
			// TODO: Throw error
			fprintf(stderr, "Can't encoded component, type unknown.\n");
		}
		Py_DECREF(item);
	}
	Py_DECREF(iterator);
	if (PyErr_Occurred()) {
		// TODO: Propagate error
	}
	return name;

}
static PyObject*
_pyccn_Name_to_ccn(PyObject* self, PyObject* args) {
	PyObject* py_name;
	struct ccn_charbuf* name;
	if (PyArg_ParseTuple(args, "O", &py_name)) {
		if (strcmp(py_name->ob_type->tp_name,"Name") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Name");
			return NULL;
		}
		name = Name_to_ccn( py_name );
	}
	return PyCObject_FromVoidPtr( (void*) name, __ccn_name_destroy );
}



// Can be called directly from c library
// For now, everything is a bytearray
//
static PyObject*
Name_from_ccn( struct ccn_charbuf* name ) {
	fprintf(stderr,"Name_from_ccn start\n");
	// Create name object
	PyObject* py_name = PyObject_CallObject(NameType, NULL);

	// Create component list
	PyObject* py_component_list = PyList_New(0);
	PyObject_SetAttrString(py_name, "components", py_component_list);

	// Iterate through name components
	// Copy into byte array
	PyObject* py_component;

	struct ccn_indexbuf* comps = ccn_indexbuf_create();
	ccn_name_split(name, comps);

	unsigned char* comp;
	int size;
	int n; // component
	int h; // header size
	for (n=0; n < comps->n -1 ; n++) {  // not the implicit digest component
		fprintf(stderr,"Name_from_ccn component %d of %d \n", n, n < comps->n -1);
		comp = &(name->buf[comps->buf[n]]) + 1;  // What is the first byte?  (250?)
		//fprintf(stderr,"\t%s\n", comp);
		for (h=2; h < (comps->buf[n+1]-comps->buf[n]); h++) {	// walk through the header until the terminators is found
			if (*(comp++) > 127) break;
		}
		size = (int) (comps->buf[n+1]-comps->buf[n])-1-h; // don't include the DTAG Component
		py_component = PyByteArray_FromStringAndSize((char*) comp, size);
		PyList_Append(py_component_list, py_component);
		Py_DECREF(py_component);
	}
	// TODO: Add implicit digest componet?
	// TODO: Parse version & segment?

	// Set ccn_data to cobject, INCRef
	PyObject* ccn_data =  PyCObject_FromVoidPtr( (void*) name, __ccn_name_destroy );
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_name, "ccn_data", ccn_data);

	ccn_indexbuf_destroy(&comps);

	fprintf(stderr,"Name_from_ccn ends\n");
	return py_name;
}

// Takes a byte array with DTAG
//
static PyObject*
Name_from_ccn_tagged_bytearray( const unsigned char* buf, size_t size) {
		PyObject* py_name;
	    struct ccn_charbuf* name = ccn_charbuf_create();
	    ccn_charbuf_append(name, buf, size);
		py_name = Name_from_ccn(name);
		ccn_charbuf_destroy(&name);
		return py_name;
}

// From within python
//
static PyObject*
_pyccn_Name_from_ccn(PyObject* self, PyObject* args) {
	PyObject* cobj_name;
	if (PyArg_ParseTuple(args, "O", &cobj_name)) {
		if (!PyCObject_Check(cobj_name)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_charbuf*");
			return NULL;
		}
		return Name_from_ccn( (struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_name) );
	}
	Py_INCREF(Py_None);
	return Py_None;
}




// ************
// Key
//
//

void __ccn_key_destroy(void* p) {
	if (p != NULL)
		ccn_pubkey_free(p);			 // what about private keys?
}

struct ccn_pkey*
Key_to_ccn_private(PyObject* py_key) {
	// TODO: Do I need to INCREF here?
	return (struct ccn_pkey*) PyCObject_AsVoidPtr( PyObject_GetAttrString(py_key, "ccn_data_private") );
}
struct ccn_pkey*
Key_to_ccn_public(PyObject* py_key) {
	// TODO: Do I need to INCREF here?
	return (struct ccn_pkey*) PyCObject_AsVoidPtr( PyObject_GetAttrString(py_key, "ccn_data_public") );
}
static PyObject*
_pyccn_generate_RSA_key(PyObject* self, PyObject* args) {
	PyObject *py_key;
	long keylen=0;
	 struct ccn_pkey *private_key, *public_key;
	 unsigned char* public_key_digest;
	 size_t public_key_digest_len;
	int result = -1;
	if (PyArg_ParseTuple(args, "Ol", &py_key, &keylen)) {
		if (strcmp(py_key->ob_type->tp_name,"Key") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Key");
			return NULL;
		}
		generate_key(keylen, &private_key, &public_key, &public_key_digest, &public_key_digest_len);

		PyObject* p;
        // privateKey
		// Don't free these here, python will call destructor
		p = PyCObject_FromVoidPtr(private_key, __ccn_key_destroy);
		PyObject_SetAttrString(py_key, "ccn_data_private", p);
		Py_INCREF(p);

        // publicKey
		// Don't free this here, python will call destructor
		p = PyCObject_FromVoidPtr(public_key, __ccn_key_destroy);
		PyObject_SetAttrString(py_key, "ccn_data_public",  p);
		Py_INCREF(p);

        // type
		p = PyString_FromString("RSA");
		PyObject_SetAttrString(py_key, "type", p);
		Py_INCREF(p);

        // publicKeyID
		p = PyByteArray_FromStringAndSize((char*)public_key_digest, public_key_digest_len);
		PyObject_SetAttrString(py_key, "publicKeyID", p);
		Py_INCREF(p);
		free (public_key_digest);

        // publicKeyIDsize
		p = PyInt_FromLong(public_key_digest_len);
		PyObject_SetAttrString(py_key, "publicKeyIDsize", p);
		Py_INCREF(p);

        // pubID
        // TODO: pubID not implemented
		p = Py_None;
		PyObject_SetAttrString(py_key, "pubID", p);
		Py_INCREF(p);


		result = 0;

	}
	return Py_BuildValue("i", result);
}
static PyObject*
_pyccn_Key_to_ccn_public(PyObject* self, PyObject* args) {
	PyObject* py_key;
	struct ccn_pkey* key;
	if (PyArg_ParseTuple(args, "O", &py_key)) {
		if (strcmp(py_key->ob_type->tp_name,"Key") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Key");
			return NULL;
		}
		key = Key_to_ccn_public(py_key);
	}
	return PyCObject_FromVoidPtr( (void*) key, __ccn_key_destroy );
}
static PyObject*
_pyccn_Key_to_ccn_private(PyObject* self, PyObject* args) {
	PyObject* py_key;
	struct ccn_pkey* key;
	if (PyArg_ParseTuple(args, "O", &py_key)) {
		if (strcmp(py_key->ob_type->tp_name,"Key") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Key");
			return NULL;
		}
		key = Key_to_ccn_private(py_key);
	}
	return PyCObject_FromVoidPtr( (void*) key, __ccn_key_destroy );
}
// Can be called directly from c library
// Note that this isn't the wire format, so we
// do a potentially redundant step here and regenerate the DER format
// so that we can do the key hash
static PyObject*
Key_from_ccn( struct ccn_pkey* key_ccn ) {

	fprintf(stderr,"Key_from_ccn start\n");

	// 1) Create python object
	PyObject* py_key = PyObject_CallObject(KeyType, NULL);



	// 2) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString


	 // If this is a private key, split private and public keys
	// There is probably a less convoluted way to do this than pulling it out to RSA
	// Also, create the digest...
	// These non-ccn functions assume the CCN defaults, RSA + SHA256
	RSA* private_key_rsa = EVP_PKEY_get1_RSA((EVP_PKEY*)key_ccn);
	struct ccn_pkey *private_key_ccn, *public_key_ccn;
	unsigned char* public_key_digest;
	size_t public_key_digest_len;
	ccn_keypair_from_rsa(private_key_rsa, &private_key_ccn, &public_key_ccn);
	create_public_key_digest(private_key_rsa, &public_key_digest, &public_key_digest_len);
	//  ccn_digest has a more convoluted API, with examples
	// in ccn_client, but *for now* it boils down to the same thing.

	// TODO:  incorporate pyOpenSSL to manipulate RSA keys?
	//

	PyObject* p;


    // type
	p = PyString_FromString("RSA");		// TODO: support others?
	PyObject_SetAttrString(py_key, "type", p);
	Py_INCREF(p);


    // publicKeyID
	p = PyByteArray_FromStringAndSize((char*)public_key_digest, public_key_digest_len);
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
	PyObject_SetAttrString(py_key, "ccn_data_public",  p);
	Py_INCREF(p);

	// 4) Return the created object

	//free(public_key_digest);

	fprintf(stderr,"Key_from_ccn ends\n");
	return py_key;
}
// From within python
//
static PyObject*
_pyccn_Key_from_ccn(PyObject* self, PyObject* args) {
	PyObject* cobj_key;
	if (PyArg_ParseTuple(args, "O", &cobj_key)) {
		if (!PyCObject_Check(cobj_key)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_pkey*");
			return NULL;
		}
		return Key_from_ccn( (struct ccn_pkey*) PyCObject_AsVoidPtr(cobj_key) );
	}
	Py_INCREF(Py_None);
	return Py_None;
}


// ************
// KeyLocator
//
//

void __ccn_key_locator_destroy(void* p) {
	if (p != NULL)
		ccn_charbuf_destroy((struct ccn_charbuf**)&p);
}


struct ccn_charbuf*
KeyLocator_to_ccn(PyObject* py_key_locator) {
	PyObject* py_keyName = PyObject_GetAttrString(py_key_locator, "keyName");
	PyObject* py_key = PyObject_GetAttrString(py_key_locator, "key");
	PyObject* py_cert = PyObject_GetAttrString(py_key_locator, "cert");
	int res = -1;
	struct ccn_charbuf *keylocator = ccn_charbuf_create();
	ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyLocator, CCN_DTAG);
	if (py_keyName != Py_None) {
		ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyName, CCN_DTAG);
		struct ccn_charbuf* name = Name_to_ccn( py_keyName );
		ccnb_append_tagged_blob(keylocator, CCN_DTAG_Name, name->buf, name->length); // check
		ccn_charbuf_destroy(&name);
		ccn_charbuf_append_closer(keylocator); /* </KeyName> */
	} else if (py_key != Py_None) {
		ccn_charbuf_append_tt(keylocator, CCN_DTAG_Key, CCN_DTAG);
		struct ccn_pkey* key = Key_to_ccn_public (py_key);;
		res = ccn_append_pubkey_blob(keylocator, key);
		free (key);
		ccn_charbuf_append_closer(keylocator); /* </Key> */
	} else if (py_cert != Py_None) {
		ccn_charbuf_append_tt(keylocator, CCN_DTAG_Certificate, CCN_DTAG);
		// TODO: How to handle certificate?  ** Not supported here
		ccn_charbuf_append_closer(keylocator); /* </Certificate> */
	}
	ccn_charbuf_append_closer(keylocator); /* </KeyLocator> */

	return keylocator;
}
static PyObject*
_pyccn_KeyLocator_to_ccn(PyObject* self, PyObject* args) {
	PyObject* py_key_locator;
	struct ccn_charbuf* key_locator;
	if (PyArg_ParseTuple(args, "O", &py_key_locator)) {
		if (strcmp(py_key_locator->ob_type->tp_name,"KeyLocator") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a KeyLocator");
			return NULL;
		}
		key_locator = KeyLocator_to_ccn(py_key_locator);
	}
	return PyCObject_FromVoidPtr( (void*) key_locator, __ccn_key_locator_destroy );
}



// Can be called directly from c library
//
//	Certificate is not supported yet, as it doesn't seem to be in CCNx.
//
static PyObject*
KeyLocator_from_ccn( struct ccn_charbuf* key_locator ) {

	// This accepts a pointer to a charbuf that begins with the DTAG_KeyLocator
	//
	fprintf(stderr,"KeyLocator_from_ccn start\n");

	// 1) Create python object
	PyObject* py_keylocator = PyObject_CallObject(KeyLocatorType, NULL);

	// 2) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString

	// Based on ccn_locate_key in ccn_client

    int res=0;
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
			 if (stop>start) {
				fprintf(stderr, "Parse CCN_DTAG_Name inside KeyName, len=%zd\n", stop-start);
				PyObject* py_name = Name_from_ccn_tagged_bytearray(d->buf +start, stop-start);
				Py_INCREF(py_name);
				PyObject_SetAttrString(py_keylocator, "name", py_name);
			 } else {
				 fprintf(stderr, "Error parsing CCN_DTAG_KeyName, res = %d\n", res);
			 }
		}
		else if (ccn_buf_match_dtag(d, CCN_DTAG_Key)) {
			const unsigned char *dkey;
			size_t dkey_size;
			ccn_parse_required_tagged_BLOB(d, CCN_DTAG_Key, 1, -1);
			stop = d->decoder.token_index;
			res = ccn_ref_tagged_BLOB(CCN_DTAG_Key, d->buf,
									  start,stop,
									  &dkey, &dkey_size);
			if (res==0) {
				fprintf(stderr, "Parse CCN_DTAG_Key, len=%zd\n", dkey_size);
				pubkey = ccn_d2i_pubkey(dkey, dkey_size);		// free with ccn_pubkey_free()
				PyObject* py_key = Key_from_ccn(pubkey); // Now the key object must destroy it.s
				Py_INCREF(py_key);
				PyObject_SetAttrString(py_keylocator, "key", py_key);
			} else {
				 fprintf(stderr, "Error parsing CCN_DTAG_Key, res = %d\n", res);
			 }
		}
		else if (ccn_buf_match_dtag(d, CCN_DTAG_Certificate)) {
			fprintf(stderr,"KeyLocator_from_ccn certificate DTAG found?? Unsupported.\n");
		}

	    ccn_buf_check_close(d);// we don't really check the parser, though-
    } else {
    	fprintf(stderr, "Parse result for Keylocator DTAG: %d\n", res);

    }
    if (res!=0) {
    	py_keylocator=Py_None;
    	Py_INCREF(py_keylocator);
    	return py_keylocator;
    }
	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	PyObject* ccn_data =  PyCObject_FromVoidPtr( (void*) key_locator, __ccn_key_locator_destroy );
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_keylocator, "ccn_data", ccn_data);




	// 4) Return the created object
	fprintf(stderr,"KeyLocator_from_ccn ends\n");
	return py_keylocator;
}
// From within python
//
static PyObject*
_pyccn_KeyLocator_from_ccn(PyObject* self, PyObject* args) {
	PyObject* cobj_key_locator;
	if (PyArg_ParseTuple(args, "O", &cobj_key_locator)) {
		if (!PyCObject_Check(cobj_key_locator)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_charbuf*");
			return NULL;
		}
		return KeyLocator_from_ccn( (struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_key_locator) );
	}
	Py_INCREF(Py_None);
	return Py_None;
}



// ************
// ExclusionFilter
//
//

void __ccn_exclusion_filter_destroy(void* p) {
	if (p != NULL)
		;
}

struct ccn_charbuf*
ExclusionFilter_to_ccn(PyObject* py_ExclusionFilter) {
	struct ccn_charbuf* sig = ccn_charbuf_create();
	//
	// Build the ExclusionFilter here.
	//
	return sig;
}
static PyObject*
_pyccn_ExclusionFilter_to_ccn(PyObject* self, PyObject* args) {
	PyObject* py_ExclusionFilter;
	struct ccn_charbuf* ExclusionFilter;
	if (PyArg_ParseTuple(args, "O", &py_ExclusionFilter)) {
		if (strcmp(py_ExclusionFilter->ob_type->tp_name,"ExclusionFilter") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass an ExclusionFilter");
			return NULL;
		}
		ExclusionFilter = ExclusionFilter_to_ccn(py_ExclusionFilter);
	}
	return PyCObject_FromVoidPtr( (void*) ExclusionFilter, __ccn_exclusion_filter_destroy );
}

// Can be called directly from c library
static PyObject*
ExclusionFilter_from_ccn( struct ccn_charbuf* ExclusionFilter ) {
	fprintf(stderr,"ExclusionFilter_from_ccn start\n");

	// 1) Create python object
	PyObject* py_exclusionfilter = PyObject_CallObject(ExclusionFilterType, NULL);

	// 2) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString
//
//    self.data = None        # shoudl this be a list?
//    # pyccn
//    self.ccn_data_dirty = False
//    self.ccn_data = None  # backing charbuf

	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	PyObject* ccn_data =  PyCObject_FromVoidPtr( (void*) ExclusionFilter, __ccn_exclusion_filter_destroy );
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_exclusionfilter, "ccn_data", ccn_data);

	// 4) Return the created object
	fprintf(stderr,"ExclusionFilter_from_ccn ends\n");
	return py_exclusionfilter;
}
// From within python
//
//TODO: Check cobjecttype
static PyObject*
_pyccn_ExclusionFilter_from_ccn(PyObject* self, PyObject* args) {
	PyObject* cobj_ExclusionFilter;
	if (PyArg_ParseTuple(args, "O", &cobj_ExclusionFilter)) {
		if (!PyCObject_Check(cobj_ExclusionFilter)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a [??]");
			return NULL;
		}
		return ExclusionFilter_from_ccn( (struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_ExclusionFilter) );
	}
	Py_INCREF(Py_None);
	return Py_None;
}


// ************
// Interest
//
//

void __ccn_interest_destroy(void* p) {
	if (p != NULL)
		ccn_charbuf_destroy( (struct ccn_charbuf**) &p);
}
void __ccn_parsed_interest_destroy(void* p) {
	if (p != NULL)
		free(p);
}

static PyObject*
_pyccn_Interest_to_ccn(PyObject* self, PyObject* args) {
	PyObject* py_interest;
	struct ccn_charbuf* interest;
	struct ccn_parsed_interest* parsed_interest;
	if (PyArg_ParseTuple(args, "O", &py_interest)) {
		if (strcmp(py_interest->ob_type->tp_name,"Interest") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass an Interest");
			return NULL;
		}
		//  Build an interest
		PyObject* p;

	    interest = ccn_charbuf_create();

	    ccn_charbuf_append_tt(interest, CCN_DTAG_Interest, CCN_DTAG);

	    ccn_charbuf_append_tt(interest, CCN_DTAG_Name, CCN_DTAG);
	    if ((p=PyObject_GetAttrString(py_interest, "name")) != Py_None) {
	    	// TODO: Name
	    }
	    ccn_charbuf_append_closer(interest); /* </Name> */

	    if ((p=PyObject_GetAttrString(py_interest, "minSuffixComponents")) != Py_None) {
		    ccnb_tagged_putf(interest, CCN_DTAG_MinSuffixComponents, "%dl", PyInt_AsLong(p));
	    }
	    if ((p=PyObject_GetAttrString(py_interest, "maxSuffixComponents")) != Py_None) {
		    ccnb_tagged_putf(interest, CCN_DTAG_MaxSuffixComponents, "%dl", PyInt_AsLong(p));
	    }
	    if ((p=PyObject_GetAttrString(py_interest, "publisherPublicKeyDigest")) != Py_None) {
	    	// TODO: publisherPublicKeyDigest
	    }
	    if ((p=PyObject_GetAttrString(py_interest, "exclude")) != Py_None) {
	    	// TODO: exclusion filter
	    }
	    if ((p=PyObject_GetAttrString(py_interest, "childSelector")) != Py_None) {
		    ccnb_tagged_putf(interest, CCN_DTAG_ChildSelector, "%dl", PyInt_AsLong(p));
	    }
	    if ((p=PyObject_GetAttrString(py_interest, "answerOriginKind")) != Py_None) {
		    ccnb_tagged_putf(interest, CCN_DTAG_AnswerOriginKind, "%dl", PyInt_AsLong(p));
	    }
	    if ((p=PyObject_GetAttrString(py_interest, "scope")) != Py_None) {
		    ccnb_tagged_putf(interest, CCN_DTAG_Scope, "%dl", PyInt_AsLong(p));
	    }
	    if ((p=PyObject_GetAttrString(py_interest, "interestLifetime")) != Py_None) {
		    ccnb_tagged_putf(interest, CCN_DTAG_InterestLifetime, "%dl", PyLong_AsLong(p));
	    }
	    if ((p=PyObject_GetAttrString(py_interest, "nonce")) != Py_None) {
	    	// TODO: Nonce
	    	// This is automatically added by the library?
	    	//
	    }

	    ccn_charbuf_append_closer(interest); /* </Interest> */

	    parsed_interest = calloc( sizeof(struct ccn_parsed_interest), 1 );
		int result = 0;
		result = ccn_parse_interest(interest->buf, interest->length, parsed_interest, NULL /* no comps */);
		// TODO: Check result

	}
	return Py_BuildValue("(OO)",
			PyCObject_FromVoidPtr( (void*) interest, __ccn_interest_destroy ),
			PyCObject_FromVoidPtr( (void*) parsed_interest, __ccn_parsed_interest_destroy));
}

// Can be called directly from c library
static PyObject*
Interest_from_ccn_parsed( struct ccn_charbuf* interest, struct ccn_parsed_interest* pi ) {
	fprintf(stderr,"KeyLocator_from_ccn start\n");

	// 1) Create python object
	PyObject* py_interest = PyObject_CallObject(InterestType, NULL);

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
	if (l>0) {
		cb = ccn_charbuf_create();	// freed by python destructor that holds the pointer
		ccn_charbuf_append(cb, interest->buf + pi->offset[CCN_PI_B_Name], l);
		p = Name_from_ccn(cb);
		PyObject_SetAttrString(py_interest, "name", p);
		Py_INCREF(p);
	}

	//        self.minSuffixComponents = None  # default 0
	l = CCN_PI_E_MinSuffixComponents - CCN_PI_B_MinSuffixComponents;
	if (l>0) {
		i =  ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_MinSuffixComponents, interest->buf,
					pi->offset[CCN_PI_B_MinSuffixComponents], pi->offset[CCN_PI_E_MinSuffixComponents]);
		p = PyInt_FromLong(i);
		PyObject_SetAttrString(py_interest, "minSuffixComponents", p);
		Py_INCREF(p);
	}

	//        self.maxSuffixComponents = None  # default infinity
	l = CCN_PI_E_MaxSuffixComponents - CCN_PI_B_MaxSuffixComponents;
	if (l>0) {
		i =  ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_MaxSuffixComponents, interest->buf,
					pi->offset[CCN_PI_B_MaxSuffixComponents], pi->offset[CCN_PI_E_MaxSuffixComponents]);
		p = PyInt_FromLong(i);
		PyObject_SetAttrString(py_interest, "maxSuffixComponents", p);
		Py_INCREF(p);
	}

	//        self.publisherPublicKeyDigest = None   # SHA256 hash
	// TODO: what is CN_PI_B_PublisherID?
	l =  CCN_PI_E_PublisherIDKeyDigest - CCN_PI_B_PublisherIDKeyDigest;
	if (l>0) {
        i = ccn_ref_tagged_BLOB(CCN_DTAG_PublisherPublicKeyDigest, interest->buf,
                                pi->offset[CCN_PI_B_PublisherIDKeyDigest],
                                pi->offset[CCN_PI_E_PublisherIDKeyDigest],
                                &blob, &blob_size);
        p = PyByteArray_FromStringAndSize((const char*) blob, blob_size);
		PyObject_SetAttrString(py_interest, "publisherPublicKeyDigest", p);
		Py_INCREF(p);
	}

	//        self.exclude = None
	l =  CCN_PI_E_Exclude -	CCN_PI_B_Exclude;
	if (l>0) {
		cb = ccn_charbuf_create();	// freed by python destructor that holds the pointer
		ccn_charbuf_append(cb, interest->buf + pi->offset[CCN_PI_B_Exclude], l);
		p = ExclusionFilter_from_ccn(cb);
		PyObject_SetAttrString(py_interest, "exclude", p);
		Py_INCREF(p);
	}

	//        self.childSelector = None
	l =  CCN_PI_E_ChildSelector - CCN_PI_B_ChildSelector;
	if (l>0) {
		i =  ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_ChildSelector, interest->buf,
					pi->offset[CCN_PI_B_ChildSelector], pi->offset[CCN_PI_E_ChildSelector]);
		p = PyInt_FromLong(i);
		PyObject_SetAttrString(py_interest, "childSelector", p);
		Py_INCREF(p);
	}

	//        self.answerOriginKind = None
	l =  CCN_PI_E_AnswerOriginKind - CCN_PI_B_AnswerOriginKind;
	if (l>0) {
		i =  ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_AnswerOriginKind, interest->buf,
					pi->offset[CCN_PI_B_AnswerOriginKind], pi->offset[CCN_PI_E_AnswerOriginKind]);
		p = PyInt_FromLong(i);
		PyObject_SetAttrString(py_interest, "answerOriginKind", p);
		Py_INCREF(p);
	}

	//        self.scope  = None
	l =  CCN_PI_E_Scope - CCN_PI_B_Scope;
	if (l>0) {
		i =  ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_Scope, interest->buf,
					pi->offset[CCN_PI_B_Scope], pi->offset[CCN_PI_E_Scope]);
		p = PyInt_FromLong(i);
		PyObject_SetAttrString(py_interest, "scope", p);
		Py_INCREF(p);
	}

	//        self.interestLifetime = None
	l =  CCN_PI_E_InterestLifetime - CCN_PI_B_InterestLifetime;
	if (l>0) {
		// From packet-ccn.c
        i = ccn_ref_tagged_BLOB(CCN_DTAG_InterestLifetime, interest->buf,
                                pi->offset[CCN_PI_B_InterestLifetime],
                                pi->offset[CCN_PI_E_InterestLifetime],
                                &blob, &blob_size);
        double lifetime = 0.0;
        for (i = 0; i < blob_size; i++)
            lifetime = lifetime * 256.0 + (double)blob[i];
        lifetime /= 4096.0;
		p = PyFloat_FromDouble(lifetime);
		PyObject_SetAttrString(py_interest, "interestLifetime", p);
		Py_INCREF(p);
	}

	//        self.nonce = None
	l =  CCN_PI_E_Nonce - CCN_PI_B_Nonce;
	if (l>0) {
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
	PyObject* ccn_data =  PyCObject_FromVoidPtr( (void*) interest, __ccn_interest_destroy );
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_interest, "ccn_data", ccn_data);
	PyObject* ccn_data_parsed =  PyCObject_FromVoidPtr( (void*) pi, __ccn_parsed_interest_destroy );
	Py_INCREF(ccn_data_parsed);
	PyObject_SetAttrString(py_interest, "ccn_data_parsed", ccn_data_parsed);

	// 4) Return the created object
	fprintf(stderr,"Interest_from_ccn ends\n");
	return py_interest;
}

// Can be called directly from c library
static PyObject*
Interest_from_ccn( struct ccn_charbuf* interest ) {
	struct ccn_parsed_interest* parsed_interest = calloc( sizeof(struct ccn_parsed_interest), 1);
	int result = 0;
	result = ccn_parse_interest(interest->buf, interest->length, parsed_interest, NULL /* no comps */);
	// TODO: Check result
	return Interest_from_ccn_parsed(interest, parsed_interest);
}

// From within python
//
static PyObject*
_pyccn_Interest_from_ccn(PyObject* self, PyObject* args) {
	PyObject* cobj_interest;
	PyObject* cobj_parsed_interest;
	if (PyArg_ParseTuple(args, "O|O", &cobj_interest, &cobj_parsed_interest)) {
		if (!PyCObject_Check(cobj_interest)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject as args");
			return NULL;
		}
		if (!PyCObject_Check(cobj_parsed_interest)) {
			return Interest_from_ccn(
					(struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_interest));
		} else {
			return Interest_from_ccn_parsed(
					(struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_interest),
					(struct ccn_parsed_interest*) PyCObject_AsVoidPtr(cobj_parsed_interest));
		}
	}
	Py_INCREF(Py_None);
	return Py_None;
}




// ************
// Signature
//
//

void __ccn_signature_destroy(void* p) {
	if (p != NULL)
		;
}

struct ccn_charbuf*
Signature_to_ccn(PyObject* py_signature) {
	struct ccn_charbuf* sig = ccn_charbuf_create();
	//
	// Build the Signature here.
	//
	return sig;
}
static PyObject*
_pyccn_Signature_to_ccn(PyObject* self, PyObject* args) {
	PyObject* py_signature;
	struct ccn_charbuf* signature;
	if (PyArg_ParseTuple(args, "O", &py_signature)) {
		if (strcmp(py_signature->ob_type->tp_name,"Signature") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Signature");
			return NULL;
		}
		signature = Signature_to_ccn(py_signature);
	}
	return PyCObject_FromVoidPtr( (void*) signature, __ccn_signature_destroy );
}

// Can be called directly from c library
static PyObject*
Signature_from_ccn( struct ccn_charbuf* signature ) {
	fprintf(stderr,"Signature_from_ccn start\n");

	// 1) Create python object
	PyObject* py_signature = PyObject_CallObject(SignatureType, NULL);

	// 2) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString

//    self.digestAlgorithm = None
//    self.witness = None
//    self.signatureBits = None
//    # pyccn
//    self.ccn_data_dirty = False
//    self.ccn_data = None  # backing charbuf

	// 3) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	PyObject* ccn_data =  PyCObject_FromVoidPtr( (void*) signature, __ccn_signature_destroy );
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_signature, "ccn_data", ccn_data);

	// 4) Return the created object
	fprintf(stderr,"Signature_from_ccn ends\n");
	return py_signature;
}
// From within python
//
static PyObject*
_pyccn_Signature_from_ccn(PyObject* self, PyObject* args) {
	PyObject* cobj_signature;
	if (PyArg_ParseTuple(args, "O", &cobj_signature)) {
		if (!PyCObject_Check(cobj_signature)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_charbuf*");
			return NULL;
		}
		return Signature_from_ccn( (struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_signature) );
	}
	Py_INCREF(Py_None);
	return Py_None;
}

// ************
// SignedInfo
//
//

void __ccn_signed_info_destroy(void* p) {
	if (p != NULL)
		ccn_charbuf_destroy((struct ccn_charbuf**)&p);
}


struct ccn_charbuf*
SignedInfo_to_ccn(PyObject* py_signed_info) {
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

    int type = (int) PyInt_AsLong ( PyObject_GetAttrString(py_signed_info, "type"));
    int freshness = (int) PyInt_AsLong( PyObject_GetAttrString(py_signed_info, "freshnessSeconds"));

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
static PyObject*
_pyccn_SignedInfo_to_ccn(PyObject* self, PyObject* args) {
	PyObject* py_signed_info;
	struct ccn_charbuf* signed_info;
	if (PyArg_ParseTuple(args, "O", &py_signed_info)) {
		if (strcmp(py_signed_info->ob_type->tp_name,"SignedInfo") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a SignedInfo");
			return NULL;
		}
		signed_info = SignedInfo_to_ccn(py_signed_info);
	}
	return PyCObject_FromVoidPtr( (void*) signed_info, __ccn_signed_info_destroy );
}

// Can be called directly from c library
//
// Pointer to a tagged blob starting with CCN_DTAG_SignedInfo
//
static PyObject*
SignedInfo_from_ccn( struct ccn_charbuf* signed_info ) {
	fprintf(stderr,"SignedInfo_from_ccn start, size=%zd\n", signed_info->length);

	// 1) Create python object
	PyObject* py_signedinfo = PyObject_CallObject(SignedInfoType, NULL);

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
    int i=0;
    d = ccn_buf_decoder_start(&decoder,
                              signed_info->buf,
                              signed_info->length);
    if (ccn_buf_match_dtag(d, CCN_DTAG_SignedInfo)) {
		ccn_buf_advance(d);
		if (ccn_buf_match_dtag(d, CCN_DTAG_PublisherPublicKeyDigest))
			start = d->decoder.token_index;
		ccn_parse_required_tagged_BLOB(d, CCN_DTAG_PublisherPublicKeyDigest, 16, 64);
		stop = d->decoder.token_index; // check - do we need this here?
		i = ccn_ref_tagged_BLOB(CCN_DTAG_PublisherPublicKeyDigest, d->buf, start, stop, &ptr, &size);
		if (i == 0) {
			//    self.publisherPublicKeyDigest = None     # SHA256 hash
			fprintf(stderr, "PyObject_SetAttrString publisherPublicKeyDigest\n");
			p = PyByteArray_FromStringAndSize((const char*)ptr, size);
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
			p = PyByteArray_FromStringAndSize((const char*)ptr, size);
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
			p = PyByteArray_FromStringAndSize((const char*)ptr, size);
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
				fprintf(stderr, "PyObject_SetAttrString finalBlockID, len=%zd\n", stop-start);
				p = PyByteArray_FromStringAndSize((const char*)(d->buf + start), stop - start);
				PyObject_SetAttrString(py_signedinfo, "finalBlockID", p);
				Py_INCREF(p);
			}
		}
		start = d->decoder.token_index;
		if (ccn_buf_match_dtag(d, CCN_DTAG_KeyLocator))
			ccn_buf_advance_past_element(d);
		stop = d->decoder.token_index;
		if (d->decoder.state >= 0 && stop > start) {
			fprintf(stderr, "PyObject_SetAttrString keyLocator, len=%zd\n", stop-start);
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
	PyObject* ccn_data =  PyCObject_FromVoidPtr( (void*) signed_info, __ccn_signed_info_destroy );
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_signedinfo, "ccn_data", ccn_data);

	// 4) Return the created object
	fprintf(stderr,"SignedInfo_from_ccn ends\n");
	return py_signedinfo;
}
// From within python
//
static PyObject*
_pyccn_SignedInfo_from_ccn(PyObject* self, PyObject* args) {
	PyObject* cobj_signed_info;
	if (PyArg_ParseTuple(args, "O", &cobj_signed_info)) {
		if (!PyCObject_Check(cobj_signed_info)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_charbuf*");
			return NULL;
		}
		return SignedInfo_from_ccn( (struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_signed_info) );
	}
	Py_INCREF(Py_None);
	return Py_None;
}


// ************
// UpcallInfo
//
//

void __ccn_upcall_info_destroy(void *p) {
	return;
	// I don't think we destroy this as it is free by the callback routines int he library...
}
// Can be called directly from c library
static PyObject*
UpcallInfo_from_ccn( struct ccn_upcall_info*  ui) {
	// Create name object
	PyObject* py_upcall_info = PyObject_CallObject(UpcallInfoType, NULL);

	//
	// Build the python UpcallInfo here
	//

	// Set ccn_data to cobject, INCRef
	// We don't have a destructor here is this object does not exist outside of the callback (for now)
	PyObject* ccn_data =  PyCObject_FromVoidPtr( (void*) ui, __ccn_upcall_info_destroy );
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_upcall_info, "ccn_data", ccn_data);

	return py_upcall_info;
}
// From within python
//
static PyObject*
_pyccn_UpcallInfo_from_ccn(PyObject* self, PyObject* args) {
	PyObject* cobj_upcall_info;
	if (PyArg_ParseTuple(args, "O", &cobj_upcall_info)) {
		if (!PyCObject_Check(cobj_upcall_info)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_upcall_info*");
			return NULL;
		}
		return UpcallInfo_from_ccn( (struct ccn_upcall_info*) PyCObject_AsVoidPtr(cobj_upcall_info) );
	}
	Py_INCREF(Py_None);
	return Py_None;
}




// ************
// ContentObject
//
//

void __ccn_content_object_destroy(void* p) {
	if (p != NULL)
		ccn_charbuf_destroy(p);
}
void __ccn_parsed_content_object_destroy(void* p) {
	if (p != NULL)
		free(p);
}
void __ccn_content_object_components_destroy(void* p) {
	if (p != NULL)
		ccn_indexbuf_destroy((struct ccn_indexbuf**) &p);
}
static PyObject*
_pyccn_ContentObject_to_ccn(PyObject* self, PyObject* args) {
	PyObject* py_content_object;
	PyObject* py_key;
	struct ccn_charbuf* content_object = ccn_charbuf_create();
	int result = -1;
	if (PyArg_ParseTuple(args, "OO", &py_content_object, &py_key)) {
		if (strcmp(py_content_object->ob_type->tp_name,"ContentObject") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a ContentObject as arg 1");
			return NULL;
		}
		if (strcmp(py_key->ob_type->tp_name,"Key") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a key as arg 2");
			return NULL;
		}
		// Build the ContentObject here.

		// Name
		struct ccn_charbuf* name = Name_to_ccn( PyObject_GetAttrString(py_content_object, "name") );

		// Content
		PyObject* py_content = PyObject_GetAttrString(py_content_object, "content");
		struct ccn_charbuf* content = ccn_charbuf_create();
		if (PyByteArray_Check(py_content)) {
			Py_ssize_t n = PyByteArray_Size(py_content);
			char* b = PyByteArray_AsString(py_content);
			ccn_charbuf_append(content, b, n);
		} else if (PyString_Check(py_content)) {		// Unicode or UTF-8?
			ccn_charbuf_append_string(content, PyString_AsString(py_content));
		} else if (PyFloat_Check(py_content) || PyLong_Check(py_content) || PyInt_Check(py_content)) {
			PyObject* s = PyObject_Str(py_content);
			ccn_charbuf_append_string(content, PyString_AsString(s));
			Py_DECREF(s);
		} else {
			// TODO: Throw error
			fprintf(stderr, "Can't encode content, type unknown.\n");
		}

		// SignedInfo
		struct ccn_charbuf* signed_info = SignedInfo_to_ccn(PyObject_GetAttrString(py_content_object, "signedInfo"));

		// DigestAlgorithm
		const char* digest_alg = NULL;
		if (PyObject_GetAttrString(py_content_object, "digestAlgorithm") != Py_None) {
			fprintf(stderr, "non-default digest algorithm not yet supported.\n");
		}

		// Key
		struct ccn_pkey* private_key = Key_to_ccn_private( py_key );

		// Encode the content object
		result = ccn_encode_ContentObject( content_object, name, signed_info, content->buf, content->length, digest_alg, private_key);
		fprintf(stderr, "ccn_encode_ContentObject res=%d\n", result);
		ccn_charbuf_destroy(&signed_info);
		ccn_charbuf_destroy(&content);
		ccn_charbuf_destroy(&name);

	}
	// TODO: don't do parsed here.
	PyObject* p = PyCObject_FromVoidPtr( (void*) content_object, __ccn_content_object_destroy );
	Py_INCREF(p); // ??
	return p;
}

// Can be called directly from c library
// may require signedinfo, signature as args
static PyObject*
ContentObject_from_ccn_parsed( struct ccn_charbuf* content_object,
							   struct ccn_parsed_ContentObject* parsed_content_object,
							   struct ccn_indexbuf* components) {


	fprintf(stderr,"ContentObject_from_ccn_parsed content_object->length=%zd\n", content_object->length);

	// Create object
	PyObject* py_co = PyObject_CallObject(ContentObjectType, NULL);

	// Name
	PyObject* py_name;
	size_t namelen = parsed_content_object->offset[CCN_PCO_E_Name] - parsed_content_object->offset[CCN_PCO_B_Name];
	fprintf(stderr,"ContentObject_from_ccn_parsed Name len=%zd\n", namelen);
	if (namelen > 0) {
		struct ccn_charbuf* name = ccn_charbuf_create();
		ccn_charbuf_append(name,  &content_object->buf[parsed_content_object->offset[CCN_PCO_B_Name]],
								  (size_t) (parsed_content_object->offset[CCN_PCO_E_Name] - parsed_content_object->offset[CCN_PCO_B_Name]));
		fprintf(stderr, "Name: ");
		dump_charbuf(name, stderr);
		fprintf(stderr, "\n");
		py_name = Name_from_ccn( name ) ;
		// ccn_charbuf_destroy(&name);		// ToDo:  Do we need this destructor?   This is called when the name is finally destroyed.
	} else {
		py_name = Py_None;
	}
	PyObject_SetAttrString(py_co, "name", py_name);
	Py_INCREF(py_name);

	// Content
	fprintf(stderr,"ContentObject_from_ccn_parsed Content\n");
	const unsigned char* value;
	size_t size;
	ccn_content_get_value( content_object->buf, content_object->length,
						   parsed_content_object, &value, &size);
	PyObject* py_content = PyByteArray_FromStringAndSize((char*)value, size);
	PyObject_SetAttrString(py_co, "content", py_content);
	Py_INCREF(py_content);

	fprintf(stderr,"ContentObject_from_ccn_parsed Signature\n");
	// TODO: Signature -- could use Interest parsing as an example
	PyObject* py_signature = Py_None;
	PyObject_SetAttrString(py_co, "signature", py_signature);
	Py_INCREF(py_signature);

	fprintf(stderr,"ContentObject_from_ccn_parsed SignedInfo\n");


	struct ccn_charbuf* signed_info = ccn_charbuf_create();
	ccn_charbuf_append(signed_info,  &content_object->buf[parsed_content_object->offset[CCN_PCO_B_SignedInfo]],
							  (size_t) (parsed_content_object->offset[CCN_PCO_E_SignedInfo] - parsed_content_object->offset[CCN_PCO_B_SignedInfo]));

	PyObject* py_signedinfo = SignedInfo_from_ccn(signed_info);  // it will destroy?
	PyObject_SetAttrString(py_co, "signedInfo", py_signedinfo);
	Py_INCREF(py_signedinfo);

	fprintf(stderr,"ContentObject_from_ccn_parsed DigestAlgorithm\n");
	PyObject* py_digestalgorithm = Py_None;  // TODO...
	PyObject_SetAttrString(py_co, "digestAlgorithm", py_digestalgorithm);
	Py_INCREF(py_digestalgorithm);

	// Set ccn_data to cobject, INCRef
	fprintf(stderr,"ContentObject_from_ccn_parsed ccn_data\n");
	PyObject* ccn_data =  PyCObject_FromVoidPtr( (void*) content_object, __ccn_content_object_destroy );
	Py_INCREF(ccn_data);
	PyObject_SetAttrString(py_co, "ccn_data", ccn_data);

	fprintf(stderr,"ContentObject_from_ccn_parsed ccn_data_parsed\n");
	PyObject* ccn_data_parsed =  PyCObject_FromVoidPtr( (void*) parsed_content_object, __ccn_parsed_content_object_destroy );
	Py_INCREF(ccn_data_parsed);
	PyObject_SetAttrString(py_co, "ccn_data_parsed", ccn_data_parsed);

	fprintf(stderr,"ContentObject_from_ccn_parsed ccn_data_components\n");
	PyObject* ccn_data_components =  PyCObject_FromVoidPtr( (void*) components, __ccn_content_object_components_destroy );
	Py_INCREF(ccn_data_components);
	PyObject_SetAttrString(py_co, "ccn_data_components", ccn_data_components);

	fprintf(stderr,"ContentObject_from_ccn_parsed complete\n");

	return py_co;

}

// Can be called directly from c library
static PyObject*
ContentObject_from_ccn( struct ccn_charbuf* content_object ) {
	struct ccn_parsed_ContentObject* parsed_content_object = calloc(sizeof(struct ccn_parsed_ContentObject),1);
	struct ccn_indexbuf* components = ccn_indexbuf_create();
	ccn_parse_ContentObject(content_object->buf, content_object->length, parsed_content_object, components);
	// TODO: Check result
	PyObject* CO = ContentObject_from_ccn_parsed(content_object, parsed_content_object, components);
	free(parsed_content_object);
	ccn_indexbuf_destroy(&components);
	return CO;
}

// From within python
//
static PyObject*
_pyccn_ContentObject_from_ccn(PyObject* self, PyObject* args) {
	PyObject* cobj_content_object;
	PyObject* cobj_parsed_content_object;
	PyObject* cobj_content_object_components;
	if (PyArg_ParseTuple(args, "O|OO", &cobj_content_object, &cobj_parsed_content_object, &cobj_content_object_components)) {
		if (!PyCObject_Check(cobj_content_object)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject as args");
			return NULL;
		}
		if (!PyCObject_Check(cobj_content_object)) {
			return ContentObject_from_ccn(
					(struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_content_object));
		} else {
			return ContentObject_from_ccn_parsed(
					(struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_content_object),
					(struct ccn_parsed_ContentObject*) PyCObject_AsVoidPtr(cobj_parsed_content_object),
					(struct ccn_indexbuf*) PyCObject_AsVoidPtr(cobj_content_object_components));
		}
	}
	Py_INCREF(Py_None);
	return Py_None;
}


// Called by destructor
//
void __ccn_destroy(void* p) {
	if (p != NULL) {
		ccn_disconnect((struct ccn*) p);		// Ok to call this even if already disconn?
		ccn_destroy((struct ccn**)&p);
	}
}


// *** Python method declarations
//
//
// ** Methods of CCN
//
// Daemon
//
// arguments: none
// returns:  CObject that is an opaque reference to the ccn handle
static PyObject* // CCN
_pyccn_ccn_create(PyObject* self, PyObject* args) {
	struct ccn* ccn_handle = ccn_create();
	return PyCObject_FromVoidPtr((void*) ccn_handle, __ccn_destroy);  // Deprecated, use capsules after 2.7.1
}




// Second argument to ccn_connect not yet supported
//
// arguments:  CObject that is an opaque reference to the ccn handle, generated by _pyccn_ccn_create
// returns:    integer, non-negative if ok (file descriptor)
//
static PyObject*
_pyccn_ccn_connect(PyObject* self, PyObject* args) {
	int result = -1;
	PyObject* ccn_handle;
	if (PyArg_ParseTuple(args, "O", &ccn_handle)) {
		if (!PyCObject_Check(ccn_handle)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a handle to ccn");
			return NULL;
		}
		result = ccn_connect((struct ccn*) PyCObject_AsVoidPtr(ccn_handle), NULL);
	}
	return Py_BuildValue("i", result);
}

// arguments:  CObject that is an opaque reference to the ccn handle, generated by _pyccn_ccn_create
// returns: integer
//
static PyObject*
_pyccn_ccn_disconnect(PyObject* self, PyObject* args) {
	int result = -1;
	PyObject* ccn_handle;
	if (PyArg_ParseTuple(args, "O", &ccn_handle)) {
		if (!PyCObject_Check(ccn_handle)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a handle to ccn");
			return NULL;
		}
		result = ccn_disconnect((struct ccn*) PyCObject_AsVoidPtr(ccn_handle));
	}
	return Py_BuildValue("i", result);
}

static PyObject* // int
_pyccn_ccn_run(PyObject* self, PyObject* args) {
	//(PyObject* timeoutms) {
	int result = -1;
	long timeoutms = 0;
	PyObject* ccn_handle;
	if (PyArg_ParseTuple(args, "Ol", &ccn_handle, &timeoutms)) {
		if (!PyCObject_Check(ccn_handle)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a handle to ccn");
			return NULL;
		}
		result = ccn_run((struct ccn*) PyCObject_AsVoidPtr(ccn_handle), timeoutms);
	}
	return Py_BuildValue("i", result);	// TODO: Slow
}

static PyObject* // int
_pyccn_ccn_set_run_timeout(PyObject* self, PyObject* args) {
	//(PyObject* timeoutms) {
	int result = -1;
	long timeoutms = 0;
	PyObject* ccn_handle;
	if (PyArg_ParseTuple(args, "Ol", &ccn_handle, &timeoutms)) {
		if (!PyCObject_Check(ccn_handle)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a handle to ccn");
			return NULL;
		}
		result = ccn_set_run_timeout( (struct ccn*) PyCObject_AsVoidPtr( ccn_handle ), timeoutms );
	}
	return Py_BuildValue("i", result);
}

static
enum ccn_upcall_res
__ccn_upcall_handler(struct ccn_closure *selfp,
        			 enum ccn_upcall_kind upcall_kind,
        			 struct ccn_upcall_info *info) {

	PyObject* py_closure = (PyObject*) selfp->data;
	PyObject* upcall_method = PyObject_GetAttrString(py_closure, "upcall");
	PyObject* py_upcall_info = UpcallInfo_from_ccn(info);
	// Refs?


	PyObject* arglist = Py_BuildValue("iO", upcall_kind, py_upcall_info);

	fprintf(stderr, "Calling upcall\n");
	PyObject* result = PyObject_CallObject(upcall_method, arglist);
	Py_DECREF(arglist);  // per docs.python.org

	return (enum ccn_upcall_res) PyInt_AsLong(result);
}

void __ccn_closure_destroy(void *p) {
	if (p !=NULL)
		free(p);
}
// Registering callbacks
static PyObject* // int
_pyccn_ccn_express_interest(PyObject* self, PyObject* args) {
	int result = -1;
	PyObject *py_ccn, *py_name, *py_closure, *py_templ; // Args
	if (PyArg_ParseTuple(args, "OOOO", &py_ccn, &py_name, &py_closure, &py_templ)) {
		if (strcmp(py_ccn->ob_type->tp_name,"CCN") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a ccn as arg 1");
			return NULL;
		}
		if (strcmp(py_name->ob_type->tp_name,"Name") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Name as arg 2");
			return NULL;
		}
		if (strcmp(py_closure->ob_type->tp_name,"Closure") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Closure as arg 3");
			return NULL;
		}
		if (strcmp(py_templ->ob_type->tp_name,"Interest") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass an Interest as arg 4");
			return NULL;
		}

		// Dereference the CCN handle, name, and template
		struct ccn* ccn = (struct ccn*) PyCObject_AsVoidPtr( PyObject_GetAttrString(py_ccn, "ccn_data") );
		struct ccn_charbuf* name = (struct ccn_charbuf*) PyCObject_AsVoidPtr( PyObject_GetAttrString(py_name, "ccn_data") );
		struct ccn_charbuf* templ = (struct ccn_charbuf*) PyCObject_AsVoidPtr( PyObject_GetAttrString(py_templ, "ccn_data") );

		// Build the closure
		struct ccn_closure *cl = (struct ccn_closure*) calloc(1, sizeof(struct ccn_closure));
		cl->p = &__ccn_upcall_handler;
		cl->data = py_closure;
		Py_INCREF(py_closure);

		// And push it into the supplied closure object
		PyObject* cobj_closure = PyCObject_FromVoidPtr( (void*) cl, __ccn_closure_destroy );
		PyObject_SetAttrString(py_closure, "ccn_data", cobj_closure);
		Py_INCREF(cobj_closure);  // TODO: Need this?

	    result = ccn_express_interest(ccn, name, cl, templ);
	}
	return Py_BuildValue("i", result);
}
static PyObject* // int
_pyccn_ccn_set_interest_filter(PyObject* self, PyObject* args) {
		// PyObject* name, PyObject* closure) {
	return 0;
}

// Simple get/put
static PyObject* // int
_pyccn_ccn_get(PyObject* self, PyObject* args) {
	PyObject* CCN;
	PyObject* name;
	PyObject* templ;
	PyObject* timeoutms;
	PyObject* py_co = Py_None;

	int result = 0;
	if (PyArg_ParseTuple(args, "OOOO", &CCN, &name, &templ, &timeoutms)) {
		if (strcmp(CCN->ob_type->tp_name,"CCN") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CCN as arg 1");
			return NULL;
		}
		if (strcmp(name->ob_type->tp_name,"Name") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Name as arg 2");
			return NULL;
		}
		if (strcmp(templ->ob_type->tp_name,"Interest") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass an Interest as arg 3");
			return NULL;
		}
		if (! (PyLong_Check(timeoutms) || PyInt_Check(timeoutms)) ) {
			PyErr_SetString(PyExc_TypeError, "Must pass an int or long as arg 4");
			return NULL;
		}

		struct ccn_charbuf* data = ccn_charbuf_create();
		struct ccn_parsed_ContentObject* pco = calloc(sizeof(struct ccn_parsed_ContentObject), 1);
		struct ccn_indexbuf* comps = ccn_indexbuf_create();
		result = ccn_get(
				(struct ccn*) PyCObject_AsVoidPtr(PyObject_GetAttrString(CCN, "ccn_data")),
				(struct ccn_charbuf*) PyCObject_AsVoidPtr(PyObject_GetAttrString(name, "ccn_data")),
				(struct ccn_charbuf*) PyCObject_AsVoidPtr(PyObject_GetAttrString(templ, "ccn_data")),
				PyLong_AsLong(timeoutms),  // will this work for int?
				data,
				pco,   // TODO: pcobuf
				comps,   // compsbuf
				0);
		fprintf(stderr, "ccn_get result=%d\n", result);
		if (result < 0) {
			py_co = Py_None;
		} else {
			py_co = ContentObject_from_ccn_parsed(data,pco,comps);
		}
		free(pco);	// TODO: freed by the destructor?
		ccn_charbuf_destroy(&data);
		ccn_indexbuf_destroy(&comps);
	}

	Py_INCREF(py_co); //?
	return py_co;
}
static PyObject* // int
_pyccn_ccn_put(PyObject* self, PyObject* args) {
	int result = -1;
	PyObject* py_ccn;
	PyObject* py_content_object;

	if (PyArg_ParseTuple(args, "OO", &py_ccn, &py_content_object)) {
		if (strcmp(py_ccn->ob_type->tp_name,"CCN") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CCN as arg 1");
			return NULL;
		}
		if (strcmp(py_content_object->ob_type->tp_name,"ContentObject") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a content object as arg 2");
			return NULL;
		}
		struct ccn_charbuf* content_object = (struct ccn_charbuf*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_content_object, "ccn_data"));


		result = ccn_put((struct ccn*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_ccn, "ccn_data")),
						 content_object->buf, content_object->length);
	}
	return Py_BuildValue("i", result);
}

// Keys
static PyObject* // int
_pyccn_ccn_load_default_key(PyObject* self, PyObject* args) {
	return 0;
}
static PyObject*  // publisherID
 _pyccn_ccn_load_private_key(PyObject* self, PyObject* args) {
		// PyObject* key) {
	return 0; // publisher ID
}
static PyObject*  // pkey
_pyccn_ccn_get_public_key(PyObject* self, PyObject* args) {
	return 0;
}


// ** Methods of ContentObject
//
// Content Objects
static PyObject* // int
_pyccn_ccn_encode_content_object(PyObject* self, PyObject* args) {
		// PyObject* key) {
	// Get everything, including ccn handle, and SignedInfo, from Content Object
	// Update signature object in content object
	return 0;
}
static PyObject* // int
_pyccn_ccn_verify_content(PyObject* self, PyObject* args) {
		// PyObject* msg) {
	return 0;
}
static PyObject* // int
_pyccn_ccn_content_matches_interest(PyObject* self, PyObject* args) {
		// PyObject* interest) {
	return 0;
}

// ** Methods of SignedInfo
//
// Signing
static PyObject* // int
_pyccn_ccn_chk_signing_params(PyObject* self, PyObject* args) {
	// Build internal signing params struct
	return 0;
}
static PyObject* // int
_pyccn_ccn_signed_info_create(PyObject* self, PyObject* args) {
	return 0;
}

// Naming
static PyObject* // int
_pyccn_ccn_name_init(PyObject* self, PyObject* args) {
	return 0;
}
static PyObject* // int
_pyccn_ccn_name_append_nonce(PyObject* self, PyObject* args) {
	return 0;
}
static PyObject*  // int
_pyccn_ccn_compare_names(PyObject* self, PyObject* args) {
		// PyObject* name) {
	return 0;
}





// Declare for python
//
static PyMethodDef PyCCNMethods[] = {

		// TODO: Fill in the help functions

		// ** Methods of CCN
		//
		{"_pyccn_ccn_create", _pyccn_ccn_create, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_connect", _pyccn_ccn_connect, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_disconnect", _pyccn_ccn_disconnect, METH_VARARGS,
		 ""},
/*		{"_pyccn_ccn_destroy", _pyccn_ccn_destroy, METH_VARARGS,
		 ""},
		 // Use del instead.
*/
		{"_pyccn_ccn_run",  _pyccn_ccn_run, METH_VARARGS,
		 ""},
		 {"_pyccn_ccn_set_run_timeout",  _pyccn_ccn_set_run_timeout, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_express_interest", _pyccn_ccn_express_interest, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_set_interest_filter", _pyccn_ccn_set_interest_filter, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_get", _pyccn_ccn_get, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_put", _pyccn_ccn_put, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_load_default_key", _pyccn_ccn_load_default_key, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_load_private_key", _pyccn_ccn_load_private_key, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_get_public_key", _pyccn_ccn_get_public_key, METH_VARARGS,
		 ""},
		{"_pyccn_generate_RSA_key", _pyccn_generate_RSA_key, METH_VARARGS,
		 ""},

		// ** Methods of ContentObject
		//
		{"_pyccn_ccn_encode_content_object", _pyccn_ccn_encode_content_object, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_verify_content", _pyccn_ccn_verify_content, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_content_matches_interest", _pyccn_ccn_content_matches_interest, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_chk_signing_params", _pyccn_ccn_chk_signing_params, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_signed_info_create", _pyccn_ccn_signed_info_create, METH_VARARGS,
		 ""},

		// Naming
		{"_pyccn_ccn_name_init", _pyccn_ccn_name_init, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_name_append_nonce", _pyccn_ccn_name_append_nonce, METH_VARARGS,
		 ""},
		{"_pyccn_ccn_compare_names", _pyccn_ccn_compare_names, METH_VARARGS,
		 ""},

		 // Converters
		 {"_pyccn_Name_to_ccn", _pyccn_Name_to_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_Name_from_ccn", _pyccn_Name_from_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_Interest_to_ccn", _pyccn_Interest_to_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_Interest_from_ccn", _pyccn_Interest_from_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_ContentObject_to_ccn", _pyccn_ContentObject_to_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_ContentObject_from_ccn", _pyccn_ContentObject_from_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_Key_to_ccn_public", _pyccn_Key_to_ccn_public, METH_VARARGS,
		  ""},
		 {"_pyccn_Key_to_ccn_private", _pyccn_Key_to_ccn_private, METH_VARARGS,
		  ""},
		 {"_pyccn_Key_from_ccn", _pyccn_Key_from_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_KeyLocator_to_ccn", _pyccn_KeyLocator_to_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_KeyLocator_from_ccn", _pyccn_KeyLocator_from_ccn, METH_VARARGS,
		  ""},
		  {"_pyccn_Signature_to_ccn", _pyccn_Signature_to_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_Signature_from_ccn", _pyccn_Signature_from_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_SignedInfo_to_ccn", _pyccn_SignedInfo_to_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_SignedInfo_from_ccn", _pyccn_SignedInfo_from_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_ExclusionFilter_to_ccn", _pyccn_ExclusionFilter_to_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_ExclusionFilter_from_ccn", _pyccn_ExclusionFilter_from_ccn, METH_VARARGS,
		  ""},
		 {"_pyccn_UpcallInfo_from_ccn", _pyccn_UpcallInfo_from_ccn, METH_VARARGS,
		  ""},

		 {NULL, NULL, 0, NULL}        /* Sentinel */
};



PyMODINIT_FUNC
init_pyccn(void)
{
    (void) Py_InitModule("_pyccn", PyCCNMethods);

    // TODO: INCREF / DECREF?
    CCNModule = PyImport_ImportModule("CCN");
    InterestModule = PyImport_ImportModule("Interest");
    ContentObjectModule = PyImport_ImportModule("ContentObject");
    ClosureModule = PyImport_ImportModule("Closure");
    KeyModule = PyImport_ImportModule("Key");
    NameModule = PyImport_ImportModule("Name");

	PyObject* CCNDict = PyModule_GetDict(CCNModule);
	PyObject* InterestDict = PyModule_GetDict(InterestModule);
	PyObject* ContentObjectDict = PyModule_GetDict(ContentObjectModule);
	PyObject* ClosureDict = PyModule_GetDict(ClosureModule);
	PyObject* KeyDict = PyModule_GetDict(KeyModule);
	PyObject* NameDict = PyModule_GetDict(NameModule);

	// These are used to instantiate new objects in C code
	CCNType = PyDict_GetItemString(CCNDict, "CCN");
	InterestType = PyDict_GetItemString(InterestDict, "Interest");
	ContentObjectType = PyDict_GetItemString(ContentObjectDict, "ContentObject");
	ClosureType = PyDict_GetItemString(ClosureDict, "Closure");
	KeyType = PyDict_GetItemString(KeyDict, "Key");
	NameType = PyDict_GetItemString(NameDict, "Name");
	// Additional
	KeyLocatorType = PyDict_GetItemString(KeyDict, "KeyLocator");
	ExclusionFilterType = PyDict_GetItemString(InterestDict, "ExclusionFilter");
	SignatureType = PyDict_GetItemString(ContentObjectDict, "Signature");
	SignedInfoType = PyDict_GetItemString(ContentObjectDict, "SignedInfo");
	UpcallInfoType = PyDict_GetItemString(ClosureDict, "UpcallInfo");

}
