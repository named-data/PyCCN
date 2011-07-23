#include <Python.h>
#include <ccn/ccn.h>
#include <ccn/hashtb.h>

#include "pyccn.h"
#include "converters.h"
#include "key_utils.h"
#include "objects.h"

// *** Python method declarations
//
//
// ** Methods of CCN
//
// Daemon
//
// arguments: none
// returns:  CObject that is an opaque reference to the ccn handle

static PyObject * // CCN
_pyccn_ccn_create(PyObject* self, PyObject* args)
{
	struct ccn *ccn_handle = ccn_create();

	if (ccn_handle < 0) {
		PyErr_SetString(g_PyExc_CCNError,
			"ccn_create() failed for an unknown reason"
			" (out of memory?).");
		return NULL;
	}

	return CCNObject_New(HANDLE, ccn_handle);
}

// Second argument to ccn_connect not yet supported
//
// arguments:  CObject that is an opaque reference to the ccn handle, generated by _pyccn_ccn_create
// returns:    integer, non-negative if ok (file descriptor)
//

static PyObject *
_pyccn_ccn_connect(PyObject* self, PyObject* args)
{
	PyObject *py_ccn_handle;
	struct ccn *handle;
	int r;

	if (!PyArg_ParseTuple(args, "O:_pyccn_ccn_connect", &py_ccn_handle))
		return NULL;

	if (!CCNObject_IsValid(HANDLE, py_ccn_handle)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Handle");
		return NULL;
	}
	handle = CCNObject_Get(HANDLE, py_ccn_handle);

	r = ccn_connect(handle, NULL);
	if (r < 0) {
		int err = ccn_geterror(handle);
		return PyErr_Format(g_PyExc_CCNError, "Unable to connect with"
			" CCN daemon: %s [%d]", strerror(err), err);
	}

	return Py_BuildValue("i", r);
}

// arguments:  CObject that is an opaque reference to the ccn handle, generated by _pyccn_ccn_create
// returns: None
//

static PyObject *
_pyccn_ccn_disconnect(PyObject* self, PyObject* args)
{
	PyObject *py_ccn_handle;
	struct ccn *handle;
	int r;

	if (!PyArg_ParseTuple(args, "O:_pyccn_ccn_disconnect", &py_ccn_handle))
		return NULL;

	if (!CCNObject_IsValid(HANDLE, py_ccn_handle)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Handle");
		return NULL;
	}
	handle = CCNObject_Get(HANDLE, py_ccn_handle);

	r = ccn_disconnect(handle);
	if (r < 0) {
		int err = ccn_geterror(handle);
		return PyErr_Format(g_PyExc_CCNError, "Unable to disconnect"
			" with CCN daemon: %s [%d]", strerror(err), err);
	}

	Py_RETURN_NONE;
}

static PyObject *
_pyccn_ccn_run(PyObject* self, PyObject* args)
{
	int r;
	PyObject *py_handle;
	int timeoutms = -1;
	struct ccn *handle;

	if (!PyArg_ParseTuple(args, "O|i:_pyccn_ccn_run",
		&py_handle, &timeoutms))
		return NULL;

	if (!CCNObject_IsValid(HANDLE, py_handle)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Handle");
		return NULL;
	}
	handle = CCNObject_Get(HANDLE, py_handle);

	Py_BEGIN_ALLOW_THREADS;
	r = ccn_run(handle, timeoutms);
	Py_END_ALLOW_THREADS;

	if (r < 0) {
		int err = ccn_geterror(handle);
		if (err == 0)
			return PyErr_Format(g_PyExc_CCNError, "ccn_run() failed"
			" for an unknown reason (possibly you're not"
			" connected to the daemon)");
		return PyErr_Format(g_PyExc_CCNError, "ccn_run() failed: %s"
			" [%d]", strerror(err), err);
	}

	Py_RETURN_NONE;
}

static PyObject * // int
_pyccn_ccn_set_run_timeout(PyObject* self, PyObject* args)
{
	int r;
	PyObject *py_handle;
	int timeoutms = 0;
	struct ccn *handle;

	if (!PyArg_ParseTuple(args, "O|i:_pyccn_ccn_set_run_timeout",
		&py_handle, &timeoutms))
		return NULL;

	if (!CCNObject_IsValid(HANDLE, py_handle)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN handle");
		return NULL;
	}
	handle = CCNObject_Get(HANDLE, py_handle);

	r = ccn_set_run_timeout(handle, timeoutms);

	return Py_BuildValue("i", r);
}

// Registering callbacks

static PyObject* // int
_pyccn_ccn_express_interest(PyObject* self, PyObject* args)
{
	int result = -1;
	PyObject *py_ccn, *py_name, *py_closure, *py_templ; // Args
	if (PyArg_ParseTuple(args, "OOOO", &py_ccn, &py_name, &py_closure, &py_templ)) {
		if (strcmp(py_ccn->ob_type->tp_name, "CCN") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a ccn as arg 1");
			return NULL;
		}
		if (strcmp(py_name->ob_type->tp_name, "Name") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Name as arg 2");
			return NULL;
		}
		if (strcmp(py_closure->ob_type->tp_name, "Closure") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Closure as arg 3");
			return NULL;
		}
		if (strcmp(py_templ->ob_type->tp_name, "Interest") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass an Interest as arg 4");
			return NULL;
		}

		// Dereference the CCN handle, name, and template
		struct ccn* ccn = (struct ccn*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_ccn, "ccn_data"));
		struct ccn_charbuf* name = (struct ccn_charbuf*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_name, "ccn_data"));
		struct ccn_charbuf* templ = (struct ccn_charbuf*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_templ, "ccn_data"));

		// Build the closure
		struct ccn_closure *cl = (struct ccn_closure*) calloc(1, sizeof(struct ccn_closure));
		cl->p = &__ccn_upcall_handler;
		cl->data = py_closure;
		Py_INCREF(py_closure);

		// And push it into the supplied closure object
		PyObject* cobj_closure = PyCObject_FromVoidPtr((void*) cl, __ccn_closure_destroy);
		PyObject_SetAttrString(py_closure, "ccn_data", cobj_closure);
		Py_INCREF(cobj_closure); // TODO: Need this?

		result = ccn_express_interest(ccn, name, cl, templ);
	}
	return Py_BuildValue("i", result);
}

static PyObject* // int
_pyccn_ccn_set_interest_filter(PyObject* self, PyObject* args)
{
	// PyObject* name, PyObject* closure) {
	return 0;
}

// Simple get/put

static PyObject* // int
_pyccn_ccn_get(PyObject* self, PyObject* args)
{
	PyObject *CCN_obj, *Name_obj, *Interest_obj, *TimeoutMS_obj;
	PyObject *py_co = Py_None;

	int result = 0;
	if (!PyArg_ParseTuple(args, "OOOO", &CCN_obj, &Name_obj, &Interest_obj, &TimeoutMS_obj))
		Py_RETURN_NONE;

	if (strcmp(CCN_obj->ob_type->tp_name, "CCN")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN as arg 1");
		return NULL;
	}

	if (strcmp(Name_obj->ob_type->tp_name, "Name")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Name as arg 2");
		return NULL;
	}

	if (strcmp(Interest_obj->ob_type->tp_name, "Interest")) {
		PyErr_SetString(PyExc_TypeError, "Must pass an Interest as arg 3");
		return NULL;
	}

	if (!PyLong_Check(TimeoutMS_obj) && !PyInt_Check(TimeoutMS_obj)) {
		PyErr_SetString(PyExc_TypeError, "Must pass an int or long as arg 4");
		return NULL;
	}

	struct ccn *ccn = PyCObject_AsVoidPtr(PyObject_GetAttrString(CCN_obj, "ccn_data"));
	struct ccn_charbuf *name = PyCObject_AsVoidPtr(PyObject_GetAttrString(Name_obj, "ccn_data"));
	struct ccn_charbuf *interest = PyCObject_AsVoidPtr(PyObject_GetAttrString(Interest_obj, "ccn_data"));
	long timeout = PyLong_AsLong(TimeoutMS_obj);

	struct ccn_charbuf* data = ccn_charbuf_create();
	struct ccn_parsed_ContentObject* pco = calloc(sizeof(struct ccn_parsed_ContentObject), 1);
	struct ccn_indexbuf* comps = ccn_indexbuf_create();

	Py_BEGIN_ALLOW_THREADS
	result = ccn_get(ccn, name, interest, timeout, data,
		pco, // TODO: pcobuf
		comps, // compsbuf
		0);
	Py_END_ALLOW_THREADS

	fprintf(stderr, "ccn_get result=%d\n", result);

	py_co = result < 0 ? Py_INCREF(Py_None), Py_None : ContentObject_from_ccn_parsed(data, pco, comps);

	ccn_indexbuf_destroy(&comps);
	free(pco); // TODO: freed by the destructor?
	ccn_charbuf_destroy(&data);

	return py_co;
}

static PyObject* // int
_pyccn_ccn_put(PyObject* self, PyObject* args)
{
	int result;
	PyObject *py_ccn, *py_content_object;

	if (!PyArg_ParseTuple(args, "OO", &py_ccn, &py_content_object))
		return Py_BuildValue("i", -1);

	if (strcmp(py_ccn->ob_type->tp_name, "CCN")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN as arg 1");
		return NULL;
	}
	if (strcmp(py_content_object->ob_type->tp_name, "ContentObject")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a content object as arg 2");
		return NULL;
	}

	PyObject *ccn_data_Content_Object = PyObject_GetAttrString(py_content_object, "ccn_data");
	struct ccn_charbuf *content_object = PyCObject_AsVoidPtr(ccn_data_Content_Object);

	result = ccn_put((struct ccn*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_ccn, "ccn_data")),
		content_object->buf, content_object->length);

	return Py_BuildValue("i", result);
}

// Keys

// TODO: Revise to make a method of CCN?
//
// args:  Key to fill, CCN Handle

static PyObject*
_pyccn_ccn_get_default_key(PyObject* self, PyObject* args)
{
	fprintf(stderr, "Got _pyccn_ccn_get_default_key start\n");
	PyObject* py_ccn;
	struct ccn_keystore* keystore;
	const struct ccn_pkey* private_key;
	if (PyArg_ParseTuple(args, "O", &py_ccn)) {
		if (strcmp(py_ccn->ob_type->tp_name, "CCN") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CCN");

			return NULL;
		}

		struct ccn_private {
			int sock;
			size_t outbufindex;
			struct ccn_charbuf *interestbuf;
			struct ccn_charbuf *inbuf;
			struct ccn_charbuf *outbuf;
			struct ccn_charbuf *ccndid;
			struct hashtb *interests_by_prefix;
			struct hashtb *interest_filters;
			struct ccn_skeleton_decoder decoder;
			struct ccn_indexbuf *scratch_indexbuf;
			struct hashtb *keys; /* public keys, by pubid */
			struct hashtb *keystores; /* unlocked private keys */
			struct ccn_charbuf *default_pubid;
			struct timeval now;
			int timeout;
			int refresh_us;
			int err; /* pos => errno value, neg => other */
			int errline;
			int verbose_error;
			int tap;
			int running;
		};

		// In order to get the default key, have to call ccn_chk_signing_params
		// which seems to get the key and insert it in the hash table; otherwise
		// the hashtable starts empty
		// Could we just have an API call that returns the default signing key?
		//
		struct ccn_private* h = (struct ccn_private*) PyCObject_AsVoidPtr(PyObject_GetAttrString(py_ccn, "ccn_data"));
		struct ccn_signing_params name_sp = CCN_SIGNING_PARAMS_INIT;
		struct ccn_signing_params p = CCN_SIGNING_PARAMS_INIT;
		struct ccn_charbuf *timestamp = NULL;
		struct ccn_charbuf *finalblockid = NULL;
		struct ccn_charbuf *keylocator = NULL;
		int res = ccn_chk_signing_params((struct ccn*) h, &name_sp, &p, &timestamp, &finalblockid, &keylocator);

		struct hashtb_enumerator ee;
		struct hashtb_enumerator *e = &ee;
		res = 0;
		hashtb_start(h->keystores, e);
		if (hashtb_seek(e, p.pubid, sizeof(p.pubid), 0) != HT_OLD_ENTRY) {
			fprintf(stderr, "No default keystore?\n");
			res = -1;
			hashtb_end(e);
			Py_INCREF(Py_None);
			return Py_None;
		} else {
			struct ccn_keystore **pk = e->data;
			keystore = *pk;
			private_key = (struct ccn_pkey*) ccn_keystore_private_key(keystore);
		}
		hashtb_end(e);

		return Key_from_ccn((struct ccn_pkey*) private_key);
	} else {

		return NULL;
	}
}

// We do not use these because working with the key storage
// in the library requires objects to have a handle to a CCN
// library, which is unnecessary.  Also, the hashtable storing
// keys in the library and keystore type itself is opaque to
// applications.
// So, Python users will have to come up with their own keystores.
/*

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
 */

// TODO: Revise Python library to make a method of Key?
//

static PyObject*
_pyccn_generate_RSA_key(PyObject* self, PyObject* args)
{
	PyObject *py_key, *p;
	long keylen = 0;
	struct ccn_pkey *private_key, *public_key;
	unsigned char* public_key_digest;
	size_t public_key_digest_len;
	int result;

	if (!PyArg_ParseTuple(args, "Ol", &py_key, &keylen))
		return Py_BuildValue("i", -1); //TODO: Throw an error

	if (strcmp(py_key->ob_type->tp_name, "Key")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Key");
		return NULL;
	}

	generate_key(keylen, &private_key, &public_key, &public_key_digest, &public_key_digest_len);

	// privateKey
	// Don't free these here, python will call destructor
	p = CCNObject_New(PKEY, private_key);
	PyObject_SetAttrString(py_key, "ccn_data_private", p);
	Py_DECREF(p);

	// publicKey
	// Don't free this here, python will call destructor
	p = CCNObject_New(PKEY, public_key);
	PyObject_SetAttrString(py_key, "ccn_data_public", p);
	Py_DECREF(p);

	// type
	p = PyString_FromString("RSA");
	PyObject_SetAttrString(py_key, "type", p);
	Py_DECREF(p);

	// publicKeyID
	p = PyByteArray_FromStringAndSize((char*) public_key_digest, public_key_digest_len);
	PyObject_SetAttrString(py_key, "publicKeyID", p);
	Py_DECREF(p);
	free(public_key_digest);

	// publicKeyIDsize
	p = PyInt_FromLong(public_key_digest_len);
	PyObject_SetAttrString(py_key, "publicKeyIDsize", p);
	Py_DECREF(p);

	// pubID
	// TODO: pubID not implemented
	p = Py_None;
	PyObject_SetAttrString(py_key, "pubID", p);

	result = 0;

	return Py_BuildValue("i", result);
}

// ** Methods of ContentObject
//
// Content Objects

static PyObject* // int
_pyccn_ccn_encode_content_object(PyObject* self, PyObject* args)
{
	// PyObject* key) {
	// Get everything, including ccn handle, and SignedInfo, from Content Object
	// Update signature object in content object

	return 0;
}

static PyObject* // int
_pyccn_ccn_verify_content(PyObject* self, PyObject* args)
{
	// PyObject* msg) {

	return 0;
}

static PyObject* // int
_pyccn_ccn_content_matches_interest(PyObject* self, PyObject* args)
{
	// PyObject* interest) {

	return 0;
}

// ** Methods of SignedInfo
//
// Signing
/* We don't expose this because ccn_signing_params is not that useful to us
 * see comments above on this.
static PyObject* // int
_pyccn_ccn_chk_signing_params(PyObject* self, PyObject* args) {
	// Build internal signing params struct
	return 0;
}
 */

/* We don't expose this because it is done automatically in the Python SignedInfo object

static PyObject*
_pyccn_ccn_signed_info_create(PyObject* self, PyObject* args) {
	return 0;
}

 */

// Naming

static PyObject* // int
_pyccn_ccn_name_init(PyObject* self, PyObject* args)
{

	return 0;
}

static PyObject* // int
_pyccn_ccn_name_append_nonce(PyObject* self, PyObject* args)
{

	return 0;
}

static PyObject* // int
_pyccn_ccn_compare_names(PyObject* self, PyObject* args)
{
	// PyObject* name) {

	return 0;
}

static PyObject*
_pyccn_Name_to_ccn(PyObject* self, PyObject* args)
{
	PyObject* py_name;
	struct ccn_charbuf* name;
	if (PyArg_ParseTuple(args, "O", &py_name)) {
		if (strcmp(py_name->ob_type->tp_name, "Name") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Name");

			return NULL;
		}
		name = Name_to_ccn(py_name);
	}
	return PyCObject_FromVoidPtr((void*) name, __ccn_name_destroy);
}

// From within python
//

static PyObject*
_pyccn_Name_from_ccn(PyObject* self, PyObject* args)
{
	PyObject* cobj_name;
	if (PyArg_ParseTuple(args, "O", &cobj_name)) {
		if (!PyCObject_Check(cobj_name)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_charbuf*");
			return NULL;
		}
		return Name_from_ccn((struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_name));
	}
	Py_INCREF(Py_None);

	return Py_None;
}

static PyObject*
_pyccn_Interest_to_ccn(PyObject* self, PyObject* args)
{
	PyObject* py_interest;
	struct ccn_charbuf* interest;
	struct ccn_parsed_interest* parsed_interest;
	if (PyArg_ParseTuple(args, "O", &py_interest)) {
		if (strcmp(py_interest->ob_type->tp_name, "Interest") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass an Interest");

			return NULL;
		}
		//  Build an interest
		interest = Interest_to_ccn(py_interest);

		parsed_interest = calloc(sizeof(struct ccn_parsed_interest), 1);
		int result = 0;
		result = ccn_parse_interest(interest->buf, interest->length, parsed_interest, NULL /* no comps */);
		// TODO: Check result

	}
	return Py_BuildValue("(OO)",
		PyCObject_FromVoidPtr((void*) interest, __ccn_interest_destroy),
		PyCObject_FromVoidPtr((void*) parsed_interest, __ccn_parsed_interest_destroy));
}

// From within python
//

static PyObject*
_pyccn_Interest_from_ccn(PyObject* self, PyObject* args)
{
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

static PyObject*
_pyccn_ContentObject_to_ccn(PyObject* self, PyObject* args)
{
	PyObject *py_content_object, *py_key;
	struct ccn_charbuf *content_object, *name;
	int result;

	if (!PyArg_ParseTuple(args, "OO:_pyccn_ContentObject_to_ccn", &py_content_object, &py_key))
		return NULL;

	if (strcmp(py_content_object->ob_type->tp_name, "ContentObject")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a ContentObject as arg 1");
		return NULL;
	}
	if (strcmp(py_key->ob_type->tp_name, "Key")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Key as arg 2");
		return NULL;
	}

	// Build the ContentObject here.
	content_object = ccn_charbuf_create();

	// Name
	name = Name_to_ccn(PyObject_GetAttrString(py_content_object, "name"));

	// Content
	PyObject* py_content = PyObject_GetAttrString(py_content_object, "content");
	struct ccn_charbuf* content = ccn_charbuf_create();
	if (PyByteArray_Check(py_content)) {
		Py_ssize_t n = PyByteArray_Size(py_content);
		char* b = PyByteArray_AsString(py_content);
		ccn_charbuf_append(content, b, n);
	} else if (PyString_Check(py_content)) { // Unicode or UTF-8?
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

	struct ccn_pkey* private_key = Key_to_ccn_private(py_key);
	// Note that we don't load this key into the keystore hashtable in the library
	// because it makes this method require access to a ccn handle, and in fact,
	// ccn_sign_content just uses what's in signedinfo (after an error check by
	// chk_signing_params and then calls ccn_encode_ContentObject anyway
	//
	// Encode the content object
	result = ccn_encode_ContentObject(content_object, name, signed_info, content->buf, content->length, digest_alg, private_key);
	fprintf(stderr, "ccn_encode_ContentObject res=%d\n", result);
	ccn_charbuf_destroy(&signed_info);
	ccn_charbuf_destroy(&content);
	ccn_charbuf_destroy(&name);

	assert(content_object);

	return CCNObject_New(CONTENT_OBJECT, content_object);
}


// From within python
//

static PyObject*
_pyccn_ContentObject_from_ccn(PyObject* self, PyObject* args)
{
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

static PyObject*
_pyccn_Key_to_ccn_public(PyObject* self, PyObject* args)
{
	PyObject* py_key;
	struct ccn_pkey* key;
	if (PyArg_ParseTuple(args, "O", &py_key)) {
		if (strcmp(py_key->ob_type->tp_name, "Key") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Key");

			return NULL;
		}
		key = Key_to_ccn_public(py_key);
	}
	return PyCObject_FromVoidPtr((void*) key, __ccn_key_destroy);
}

static PyObject*
_pyccn_Key_to_ccn_private(PyObject* self, PyObject* args)
{
	PyObject* py_key;
	struct ccn_pkey* key;
	if (PyArg_ParseTuple(args, "O", &py_key)) {
		if (strcmp(py_key->ob_type->tp_name, "Key") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Key");

			return NULL;
		}
		key = Key_to_ccn_private(py_key);
	}
	return PyCObject_FromVoidPtr((void*) key, __ccn_key_destroy);
}

static PyObject*
_pyccn_Key_from_ccn(PyObject* self, PyObject* args)
{
	PyObject* cobj_key;
	if (PyArg_ParseTuple(args, "O", &cobj_key)) {
		if (!PyCObject_Check(cobj_key)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_pkey*");
			return NULL;
		}
		return Key_from_ccn((struct ccn_pkey*) PyCObject_AsVoidPtr(cobj_key));
	}
	Py_INCREF(Py_None);

	return Py_None;
}

static PyObject*
_pyccn_KeyLocator_to_ccn(PyObject* self, PyObject* args)
{
	PyObject* py_key_locator;
	struct ccn_charbuf* key_locator;
	if (PyArg_ParseTuple(args, "O", &py_key_locator)) {
		if (strcmp(py_key_locator->ob_type->tp_name, "KeyLocator") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a KeyLocator");

			return NULL;
		}
		key_locator = KeyLocator_to_ccn(py_key_locator);
	}
	return PyCObject_FromVoidPtr((void*) key_locator, __ccn_key_locator_destroy);
}

// From within python
//

static PyObject*
_pyccn_KeyLocator_from_ccn(PyObject* self, PyObject* args)
{
	PyObject* cobj_key_locator;
	if (PyArg_ParseTuple(args, "O", &cobj_key_locator)) {
		if (!PyCObject_Check(cobj_key_locator)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_charbuf*");
			return NULL;
		}
		return KeyLocator_from_ccn((struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_key_locator));
	}
	Py_INCREF(Py_None);

	return Py_None;
}

static PyObject*
_pyccn_Signature_to_ccn(PyObject* self, PyObject* args)
{
	PyObject* py_signature;
	struct ccn_charbuf* signature;
	if (PyArg_ParseTuple(args, "O", &py_signature)) {
		if (strcmp(py_signature->ob_type->tp_name, "Signature") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a Signature");

			return NULL;
		}
		signature = Signature_to_ccn(py_signature);
	}
	return PyCObject_FromVoidPtr((void*) signature, __ccn_signature_destroy);
}

// From within python
//

static PyObject*
_pyccn_Signature_from_ccn(PyObject* self, PyObject* args)
{
	PyObject* cobj_signature;
	if (PyArg_ParseTuple(args, "O", &cobj_signature)) {
		if (!PyCObject_Check(cobj_signature)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_charbuf*");
			return NULL;
		}
		return Signature_from_ccn((struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_signature));
	}
	Py_INCREF(Py_None);

	return Py_None;
}

static PyObject*
_pyccn_SignedInfo_to_ccn(PyObject* self, PyObject* args)
{
	PyObject* py_signed_info;
	struct ccn_charbuf* signed_info;
	if (PyArg_ParseTuple(args, "O", &py_signed_info)) {
		if (strcmp(py_signed_info->ob_type->tp_name, "SignedInfo") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass a SignedInfo");

			return NULL;
		}
		signed_info = SignedInfo_to_ccn(py_signed_info);
	}
	return PyCObject_FromVoidPtr((void*) signed_info, __ccn_signed_info_destroy);
}

// From within python
//

static PyObject*
_pyccn_SignedInfo_from_ccn(PyObject* self, PyObject* args)
{
	PyObject* cobj_signed_info;
	if (PyArg_ParseTuple(args, "O", &cobj_signed_info)) {
		if (!PyCObject_Check(cobj_signed_info)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_charbuf*");
			return NULL;
		}
		return SignedInfo_from_ccn((struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_signed_info));
	}
	Py_INCREF(Py_None);

	return Py_None;
}

// From within python
//

static PyObject*
_pyccn_SigningParams_from_ccn(PyObject* self, PyObject* args)
{
	PyObject* cobj_signing_params;
	if (PyArg_ParseTuple(args, "O", &cobj_signing_params)) {
		if (!PyCObject_Check(cobj_signing_params)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_signing_params*");
			return NULL;
		}
		return SigningParams_from_ccn((struct ccn_signing_params*) PyCObject_AsVoidPtr(cobj_signing_params));
	}
	Py_INCREF(Py_None);

	return Py_None;
}

static PyObject*
_pyccn_ExclusionFilter_to_ccn(PyObject* self, PyObject* args)
{
	PyObject* py_ExclusionFilter;
	struct ccn_charbuf* ExclusionFilter;
	if (PyArg_ParseTuple(args, "O", &py_ExclusionFilter)) {
		if (strcmp(py_ExclusionFilter->ob_type->tp_name, "ExclusionFilter") != 0) {
			PyErr_SetString(PyExc_TypeError, "Must pass an ExclusionFilter");

			return NULL;
		}
		ExclusionFilter = ExclusionFilter_to_ccn(py_ExclusionFilter);
	}
	return PyCObject_FromVoidPtr((void*) ExclusionFilter, __ccn_exclusion_filter_destroy);
}

static PyObject*
_pyccn_ExclusionFilter_from_ccn(PyObject* self, PyObject* args)
{
	PyObject* cobj_ExclusionFilter;
	if (PyArg_ParseTuple(args, "O", &cobj_ExclusionFilter)) {
		if (!PyCObject_Check(cobj_ExclusionFilter)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a [??]");
			return NULL;
		}
		return ExclusionFilter_from_ccn((struct ccn_charbuf*) PyCObject_AsVoidPtr(cobj_ExclusionFilter));
	}
	Py_INCREF(Py_None);

	return Py_None;
}

static PyObject*
_pyccn_UpcallInfo_from_ccn(PyObject* self, PyObject* args)
{
	PyObject* cobj_upcall_info;
	if (PyArg_ParseTuple(args, "O", &cobj_upcall_info)) {
		if (!PyCObject_Check(cobj_upcall_info)) {
			PyErr_SetString(PyExc_TypeError, "Must pass a CObject containing a struct ccn_upcall_info*");
			return NULL;
		}
		return UpcallInfo_from_ccn((struct ccn_upcall_info*) PyCObject_AsVoidPtr(cobj_upcall_info));
	}
	Py_INCREF(Py_None);

	return Py_None;
}

// DECLARATION OF PYTHON-ACCESSIBLE FUNCTIONS
//

static PyMethodDef _module_methods[] = {

	// ** Methods of CCN
	//
	{"_pyccn_ccn_create", _pyccn_ccn_create, METH_VARARGS,
		""},
	{"_pyccn_ccn_connect", _pyccn_ccn_connect, METH_VARARGS,
		""},
	{"_pyccn_ccn_disconnect", _pyccn_ccn_disconnect, METH_VARARGS,
		""},
	{"_pyccn_ccn_run", _pyccn_ccn_run, METH_VARARGS,
		""},
	{"_pyccn_ccn_set_run_timeout", _pyccn_ccn_set_run_timeout, METH_VARARGS,
		""},
	{"_pyccn_ccn_express_interest", _pyccn_ccn_express_interest, METH_VARARGS,
		""},
	{"_pyccn_ccn_set_interest_filter", _pyccn_ccn_set_interest_filter, METH_VARARGS,
		""},
	{"_pyccn_ccn_get", _pyccn_ccn_get, METH_VARARGS,
		""},
	{"_pyccn_ccn_put", _pyccn_ccn_put, METH_VARARGS,
		""},
	{"_pyccn_ccn_get_default_key", _pyccn_ccn_get_default_key, METH_VARARGS,
		""},
#if 0
	{"_pyccn_ccn_load_default_key", _pyccn_ccn_load_default_key, METH_VARARGS,
		""},
	{"_pyccn_ccn_load_private_key", _pyccn_ccn_load_private_key, METH_VARARGS,
		""},
	{"_pyccn_ccn_get_public_key", _pyccn_ccn_get_public_key, METH_VARARGS,
		""},
#endif
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
#if 0
	{"_pyccn_ccn_chk_signing_params", _pyccn_ccn_chk_signing_params, METH_VARARGS,
		""},
	{"_pyccn_ccn_signed_info_create", _pyccn_ccn_signed_info_create, METH_VARARGS,
		""},
#endif
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
#if 0
	{"_pyccn_SignedInfo_to_ccn", _pyccn_SigningParams_to_ccn, METH_VARARGS,
		""},
#endif
	{"_pyccn_SignedInfo_from_ccn", _pyccn_SigningParams_from_ccn, METH_VARARGS,
		""},
	{"_pyccn_ExclusionFilter_to_ccn", _pyccn_ExclusionFilter_to_ccn, METH_VARARGS,
		""},
	{"_pyccn_ExclusionFilter_from_ccn", _pyccn_ExclusionFilter_from_ccn, METH_VARARGS,
		""},
	{"_pyccn_UpcallInfo_from_ccn", _pyccn_UpcallInfo_from_ccn, METH_VARARGS,
		""},

	{NULL, NULL, 0, NULL} /* Sentinel */
};

PyObject *
initialize_methods(const char* name)
{
	return Py_InitModule(name, _module_methods);
}