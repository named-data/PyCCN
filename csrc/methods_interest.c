/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#include "python_hdr.h"
#include <ccn/ccn.h>

#include "pyccn.h"
#include "util.h"
#include "methods_name.h"
#include "methods_interest.h"
#include "objects.h"

static int
is_attr_set(PyObject *py_obj, const char *attr, PyObject **value)
{
	PyObject *py_attr;

	assert(value);

	py_attr = PyObject_GetAttrString(py_obj, attr);
	if (!py_attr)
		return -1;

	if (py_attr == Py_None) {
		Py_DECREF(py_attr);
		return 0;
	}

	*value = py_attr;

	return 1;
}

// ************
// ExclusionFilter
//
//

static PyObject *
ExclusionFilter_names_to_ccn(PyObject *py_obj_Names)
{
	PyObject *py_iterator = NULL, *py_item = NULL;
	PyObject *py_exclude, *py_o;
	struct ccn_charbuf *exclude, *name;
	int r;

	//  Build exclusion list - This uses explicit exclusion rather than
	//                         Bloom filters as Bloom will be deprecated
	//  IMPORTANT:  Exclusion component list must be sorted following
	//              "Canonical CCNx ordering"
	//              http://www.ccnx.org/releases/latest/doc/technical/CanonicalOrder.html
	//              in which shortest components go first.
	// This sorting is expected to be handled on the Python side, not here.

	assert(py_obj_Names);

	py_exclude = CCNObject_New_charbuf(EXCLUSION_FILTER, &exclude);
	JUMP_IF_NULL(py_exclude, error);

	if (py_obj_Names == Py_None)
		return py_exclude;

	r = ccn_charbuf_append_tt(exclude, CCN_DTAG_Exclude, CCN_DTAG);
	JUMP_IF_NEG_MEM(r, error);

	// This code is similar to what's used in Name;
	// could probably be generalized.

	py_iterator = PyObject_GetIter(py_obj_Names);
	JUMP_IF_NULL(py_iterator, error);

	while ((py_item = PyIter_Next(py_iterator))) {
		int type;

		if (!PyObject_IsInstance(py_item, g_type_Name)) {
			PyErr_SetString(PyExc_ValueError, "Expected Name element");
			goto error;
		}

		py_o = PyObject_GetAttrString(py_item, "type");
		JUMP_IF_NULL(py_o, error);

		type = PyLong_AsLong(py_o);
		Py_DECREF(py_o);
		JUMP_IF_ERR(error);

		if (type == 0) {
			py_o = PyObject_GetAttrString(py_item, "ccn_data");
			JUMP_IF_NULL(py_o, error);

			if (!CCNObject_IsValid(NAME, py_o)) {
				Py_DECREF(py_o);
				PyErr_SetString(PyExc_TypeError, "Expected CCN Name");
				goto error;
			}

			name = CCNObject_Get(NAME, py_o);

			/* append without CCN name tag */
			assert(name->length >= 4);
			r = ccn_charbuf_append(exclude, name->buf + 1, name->length - 2);
			Py_DECREF(py_o);
			JUMP_IF_NEG_MEM(r, error);
		} else if (type == 1) {
			r = ccn_charbuf_append_tt(exclude, CCN_DTAG_Any, CCN_DTAG);
			JUMP_IF_NEG_MEM(r, error);

			r = ccn_charbuf_append_closer(exclude);
			JUMP_IF_NEG_MEM(r, error);
		} else {
			PyErr_SetString(PyExc_ValueError, "Unhandled Name type");
			goto error;
		}

		Py_CLEAR(py_item);
	}
	Py_CLEAR(py_iterator);

	r = ccn_charbuf_append_closer(exclude); /* </Exclude> */
	JUMP_IF_NEG_MEM(r, error);

	return py_exclude;

error:
	Py_XDECREF(py_item);
	Py_XDECREF(py_iterator);
	Py_XDECREF(py_exclude);
	return NULL;
}

static PyObject *
Exclusion_Any_Obj(void)
{
	PyObject *py_o, *py_kwds;
	int r;

	assert(g_type_Name);

	py_kwds = PyDict_New();
	JUMP_IF_NULL(py_kwds, error);

	py_o = PyLong_FromLong(NAME_TYPE_ANY);
	JUMP_IF_NULL(py_o, error);

	r = PyDict_SetItemString(py_kwds, "name_type", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);

	py_o = PyEval_CallObjectWithKeywords(g_type_Name, NULL, py_kwds);
	Py_CLEAR(py_kwds);

	return py_o;

error:
	Py_XDECREF(py_kwds);
	return NULL;
}

static PyObject *
Exclusion_Name_Obj(unsigned char *buf, size_t start, size_t stop)
{
	struct ccn_charbuf *name;
	PyObject *py_name, *res;
	int r;

	py_name = CCNObject_New_charbuf(NAME, &name);
	JUMP_IF_NULL(py_name, error);

	r = ccn_name_init(name);
	JUMP_IF_NEG_MEM(r, error);

	r = ccn_name_append_components(name, buf, start, stop);
	JUMP_IF_NEG_MEM(r, error);

	res = Name_obj_from_ccn(py_name);
	Py_DECREF(py_name);

	return res;

error:
	Py_XDECREF(py_name);
	return NULL;
}

static PyObject *
ExclusionFilter_obj_from_ccn(PyObject *py_exclusion_filter)
{
	PyObject *py_obj_ExclusionFilter, *py_components = NULL;
	PyObject *py_o;
	struct ccn_charbuf *exclusion_filter;
	int r;
	struct ccn_buf_decoder decoder, *d;
	size_t start, stop;

	assert(g_type_ExclusionFilter);

	debug("ExclusionFilter_from_ccn start\n");

	exclusion_filter = CCNObject_Get(EXCLUSION_FILTER, py_exclusion_filter);

	// 1) Create python object
	py_obj_ExclusionFilter = PyObject_CallObject(g_type_ExclusionFilter, NULL);
	JUMP_IF_NULL(py_obj_ExclusionFilter, error);

	// 2) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	r = PyObject_SetAttrString(py_obj_ExclusionFilter, "ccn_data",
			py_exclusion_filter);
	JUMP_IF_NEG(r, error);

	// 3) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString
	//
	//    self.components = None
	//    # pyccn
	//    self.ccn_data_dirty = False
	//    self.ccn_data = None  # backing charbuf

	py_components = PyList_New(0);
	JUMP_IF_NULL(py_components, error);

	r = PyObject_SetAttrString(py_obj_ExclusionFilter, "components",
			py_components);
	JUMP_IF_NEG(r, error);

	/* begin the actual parsing */
	d = ccn_buf_decoder_start(&decoder, exclusion_filter->buf,
			exclusion_filter->length);

	r = ccn_buf_match_dtag(d, CCN_DTAG_Exclude);
	JUMP_IF_NEG(r, parse_error);
	ccn_buf_advance(d);

	r = ccn_buf_match_dtag(d, CCN_DTAG_Any);
	JUMP_IF_NEG(r, error);
	if (r) {
		ccn_buf_advance(d);
		ccn_buf_check_close(d);
		debug("got any: %d\n", r);

		py_o = Exclusion_Any_Obj();
		JUMP_IF_NULL(py_o, error);

		r = PyList_Append(py_components, py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	while (ccn_buf_match_dtag(d, CCN_DTAG_Component)) {
		start = d->decoder.token_index;
		r = ccn_parse_required_tagged_BLOB(d, CCN_DTAG_Component, 0, -1);
		JUMP_IF_NEG(r, error);
		stop = d->decoder.token_index;
		debug("got name\n");

		py_o = Exclusion_Name_Obj(exclusion_filter->buf, start, stop);
		r = PyList_Append(py_components, py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);

		r = ccn_buf_match_dtag(d, CCN_DTAG_Any);
		if (r) {
			ccn_buf_advance(d);
			ccn_buf_check_close(d);
			debug("got *any*: %d\n", r);

			py_o = Exclusion_Any_Obj();
			JUMP_IF_NULL(py_o, error);

			r = PyList_Append(py_components, py_o);
			Py_DECREF(py_o);
			JUMP_IF_NEG(r, error);
		}
	}
	ccn_buf_check_close(d);
	JUMP_IF_NEG(d->decoder.state, parse_error);

	// 4) Return the created object
	debug("ExclusionFilter_from_ccn ends\n");

	return py_obj_ExclusionFilter;

parse_error:
	PyErr_SetString(g_PyExc_CCNExclusionFilterError, "error parsing the data");
error:
	Py_XDECREF(py_components);
	Py_XDECREF(py_obj_ExclusionFilter);
	return NULL;
}

// ************
// Interest
//
//

static int
process_int_attribute(struct ccn_charbuf *interest, enum ccn_dtag tag,
		PyObject *py_obj_Interest, const char *attr_name)
{
	PyObject *py_attr;
	int val, r;

	r = is_attr_set(py_obj_Interest, attr_name, &py_attr);
	if (r <= 0)
		return r;

	val = _pyccn_Int_AsLong(py_attr);
	Py_DECREF(py_attr);
	if (PyErr_Occurred())
		return -1;

#if 0
	r = ccn_charbuf_append_tt(interest, tag, CCN_DTAG);
	JUMP_IF_NEG_MEM(r, error);

	r = ccnb_append_number(interest, val);
	JUMP_IF_NEG_MEM(r, error);

	r = ccn_charbuf_append_closer(interest); /* </Tag> */
	JUMP_IF_NEG_MEM(r, error);
#endif

	r = ccnb_tagged_putf(interest, tag, "%d", val);
	JUMP_IF_NEG_MEM(r, error);

	return 1;
error:
	return -1;
}

static PyObject *
Interest_obj_to_ccn(PyObject *py_obj_Interest)
{
	struct ccn_charbuf *interest;
	PyObject *py_interest, *py_o;
	int r;

	py_interest = CCNObject_New_charbuf(INTEREST, &interest);
	if (!py_interest)
		return NULL;

	r = ccn_charbuf_append_tt(interest, CCN_DTAG_Interest, CCN_DTAG);
	JUMP_IF_NEG_MEM(r, error);

	/* Name */
	{
		struct ccn_charbuf *name;
		PyObject *py_name;

		r = is_attr_set(py_obj_Interest, "name", &py_o);
		JUMP_IF_NEG(r, error);

		if (r) {
			py_name = Name_obj_to_ccn(py_o);
			Py_DECREF(py_o);
			JUMP_IF_NULL(py_name, error);
			name = CCNObject_Get(NAME, py_name);

			r = ccn_charbuf_append_charbuf(interest, name);
			Py_DECREF(py_name);
			JUMP_IF_NEG_MEM(r, error);
		} else {
			// Even though Name is mandatory we still use this code to generate
			// templates, so it is ok if name is not given, the code below
			// creates an empty tag
			r = ccn_charbuf_append_tt(interest, CCN_DTAG_Name, CCN_DTAG);
			JUMP_IF_NEG(r, error);

			r = ccn_charbuf_append_closer(interest); /* </Name> */
			JUMP_IF_NEG(r, error);
		}
	}

	r = process_int_attribute(interest, CCN_DTAG_MinSuffixComponents,
			py_obj_Interest, "minSuffixComponents");
	JUMP_IF_NEG(r, error);

	r = process_int_attribute(interest, CCN_DTAG_MaxSuffixComponents,
			py_obj_Interest, "maxSuffixComponents");
	JUMP_IF_NEG(r, error);

	r = is_attr_set(py_obj_Interest, "publisherPublicKeyDigest", &py_o);
	JUMP_IF_NEG(r, error);
	if (r) {
		const char *blob;
		Py_ssize_t blobsize;

		blob = PyBytes_AsString(py_o);
		if (!blob) {
			Py_DECREF(py_o);
			goto error;
		}
		blobsize = PyBytes_GET_SIZE(py_o);

		r = ccnb_append_tagged_blob(interest, CCN_DTAG_PublisherPublicKeyDigest,
				blob, blobsize);
		Py_DECREF(py_o);
		JUMP_IF_NEG_MEM(r, error);
	}

	r = is_attr_set(py_obj_Interest, "exclude", &py_o);
	JUMP_IF_NEG(r, error);
	if (r) {
		PyObject *py_exclusions;
		struct ccn_charbuf *exclusion_filter;

		if (!PyObject_IsInstance(py_o, g_type_ExclusionFilter)) {
			Py_DECREF(py_o);
			PyErr_SetString(PyExc_TypeError, "Expected ExclusionFilter");
			goto error;
		}

		r = is_attr_set(py_o, "ccn_data", &py_exclusions);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);

		exclusion_filter = CCNObject_Get(EXCLUSION_FILTER, py_exclusions);
		r = ccn_charbuf_append_charbuf(interest, exclusion_filter);
		Py_DECREF(py_exclusions);
		JUMP_IF_NEG(r, error);
	}

	r = process_int_attribute(interest, CCN_DTAG_ChildSelector,
			py_obj_Interest, "childSelector");
	JUMP_IF_NEG(r, error);

	r = process_int_attribute(interest, CCN_DTAG_AnswerOriginKind,
			py_obj_Interest, "answerOriginKind");
	JUMP_IF_NEG(r, error);

	r = process_int_attribute(interest, CCN_DTAG_Scope, py_obj_Interest,
			"scope");
	JUMP_IF_NEG(r, error);

	r = is_attr_set(py_obj_Interest, "interestLifetime", &py_o);
	if (r) {
		unsigned char buf[3] = {0};
		double lifetime;
		unsigned long i_lifetime;

		if (!PyFloat_Check(py_o)) {
			Py_DECREF(py_o);
			PyErr_SetString(PyExc_TypeError, "expected float type in interest"
					" lifetime");
			goto error;
		}

		lifetime = PyFloat_AS_DOUBLE(py_o);
		Py_DECREF(py_o);

		i_lifetime = lifetime * 4096;

		/* XXX: probably won't work in bigendian */
		for (int i = sizeof(buf) - 1; i >= 0; i--, i_lifetime >>= 8)
			buf[i] = i_lifetime & 0xff;

		r = ccnb_append_tagged_blob(interest, CCN_DTAG_InterestLifetime,
				buf, sizeof(buf));
		JUMP_IF_NEG_MEM(r, error);
	}

	r = is_attr_set(py_obj_Interest, "nonce", &py_o);
	if (r) {
		char *s;
		Py_ssize_t len;

		r = PyBytes_AsStringAndSize(py_o, &s, &len);
		if (r < 0) {
			Py_DECREF(py_o);
			goto error;
		}

		r = ccnb_append_tagged_blob(interest, CCN_DTAG_Nonce, s, len);
		Py_DECREF(py_o);
		JUMP_IF_NEG_MEM(r, error);
	}

	r = ccn_charbuf_append_closer(interest); /* </Interest> */
	JUMP_IF_NEG_MEM(r, error);

	return py_interest;

error:
	Py_DECREF(py_interest);

	return NULL;
}

PyObject *
Interest_obj_from_ccn(PyObject *py_interest)
{
	struct ccn_charbuf *interest;
	struct ccn_parsed_interest *pi;
	PyObject *py_obj_Interest, *py_o;
	int r;

	debug("Interest_from_ccn_parsed start\n");

	interest = CCNObject_Get(INTEREST, py_interest);

	// 1) Create python object
	py_obj_Interest = PyObject_CallObject(g_type_Interest, NULL);
	if (!py_obj_Interest)
		return NULL;

	pi = _pyccn_interest_get_pi(py_interest);
	JUMP_IF_NULL(pi, error);

	// 2) Set ccn_data to a cobject pointing to the c struct
	//    and ensure proper destructor is set up for the c object.
	r = PyObject_SetAttrString(py_obj_Interest, "ccn_data", py_interest);
	JUMP_IF_NEG(r, error);

	// 3) Parse c structure and fill python attributes
	//    using PyObject_SetAttrString

	ssize_t len;
	const unsigned char *blob;
	size_t blob_size, start, end;
	struct ccn_charbuf * cb;

	// Best decoding examples are in packet-ccn.c for wireshark plugin?

	//        self.name = None  # Start from None to use for templates?
	len = pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name];
	if (len > 0) {
		PyObject *py_cname;

		py_cname = CCNObject_New_charbuf(NAME, &cb);
		JUMP_IF_NULL(py_cname, error);

		r = ccn_charbuf_append(cb, interest->buf + pi->offset[CCN_PI_B_Name],
				len);
		JUMP_IF_NEG_MEM(r, error);

		py_o = Name_obj_from_ccn(py_cname);
		Py_DECREF(py_cname);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_Interest, "name", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	} else {
		PyErr_SetString(g_PyExc_CCNInterestError, "Got interest without a"
				" name!");
		goto error;
	}

	//        self.minSuffixComponents = None  # default 0
	len = pi->offset[CCN_PI_E_MinSuffixComponents] -
			pi->offset[CCN_PI_B_MinSuffixComponents];
	if (len > 0) {
		r = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_MinSuffixComponents,
				interest->buf, pi->offset[CCN_PI_B_MinSuffixComponents],
				pi->offset[CCN_PI_E_MinSuffixComponents]);
		if (r < 0) {
			PyErr_SetString(g_PyExc_CCNInterestError, "Invalid"
					" MinSuffixComponents value");
			goto error;
		}

		py_o = _pyccn_Int_FromLong(r);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_Interest, "minSuffixComponents",
				py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	//        self.maxSuffixComponents = None  # default infinity
	len = pi->offset[CCN_PI_E_MaxSuffixComponents] -
			pi->offset[CCN_PI_B_MaxSuffixComponents];
	if (len > 0) {
		r = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_MaxSuffixComponents,
				interest->buf, pi->offset[CCN_PI_B_MaxSuffixComponents],
				pi->offset[CCN_PI_E_MaxSuffixComponents]);
		if (r < 0) {
			PyErr_SetString(g_PyExc_CCNInterestError, "Invalid"
					" MaxSuffixComponents value");
			goto error;
		}

		py_o = _pyccn_Int_FromLong(r);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_Interest, "maxSuffixComponents",
				py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	//        self.publisherPublicKeyDigest = None   # SHA256 hash
	// TODO: what is CN_PI_B_PublisherID? -- looks like it is the data including
	//                                       the tags while PublisherIDKeyDigest
	//                                       is just the raw digest -- dk
	start = pi->offset[CCN_PI_B_PublisherID];
	end = pi->offset[CCN_PI_E_PublisherID];
	len = end - start;
	if (len > 0) {
		r = ccn_ref_tagged_BLOB(CCN_DTAG_PublisherPublicKeyDigest,
				interest->buf, start, end, &blob, &blob_size);
		if (r < 0) {
			PyErr_SetString(g_PyExc_CCNInterestError, "Invalid"
					" PublisherPublicKeyDigest value");
			goto error;
		}

		py_o = PyBytes_FromStringAndSize((const char*) blob, blob_size);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_Interest, "publisherPublicKeyDigest",
				py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	//        self.exclude = None
	len = pi->offset[CCN_PI_E_Exclude] - pi->offset[CCN_PI_B_Exclude];
	if (len > 0) {
		PyObject *py_exclusion_filter;

		py_exclusion_filter = CCNObject_New_charbuf(EXCLUSION_FILTER, &cb);
		JUMP_IF_NULL(py_exclusion_filter, error);

		r = ccn_charbuf_append(cb, interest->buf + pi->offset[CCN_PI_B_Exclude],
				len);
		JUMP_IF_NEG_MEM(r, error);

		py_o = ExclusionFilter_obj_from_ccn(py_exclusion_filter);
		Py_DECREF(py_exclusion_filter);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_Interest, "exclude", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	//        self.childSelector = None
	len = pi->offset[CCN_PI_E_ChildSelector] -
			pi->offset[CCN_PI_B_ChildSelector];
	if (len > 0) {
		r = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_ChildSelector,
				interest->buf, pi->offset[CCN_PI_B_ChildSelector],
				pi->offset[CCN_PI_E_ChildSelector]);
		if (r < 0) {
			PyErr_SetString(g_PyExc_CCNInterestError, "Invalid"
					" ChildSelector value");
			goto error;
		}

		py_o = _pyccn_Int_FromLong(r);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_Interest, "childSelector", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	//        self.answerOriginKind = None
	len = pi->offset[CCN_PI_E_AnswerOriginKind] -
			pi->offset[CCN_PI_B_AnswerOriginKind];
	if (len > 0) {
		r = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_AnswerOriginKind,
				interest->buf, pi->offset[CCN_PI_B_AnswerOriginKind],
				pi->offset[CCN_PI_E_AnswerOriginKind]);
		if (r < 0) {
			PyErr_SetString(g_PyExc_CCNInterestError, "Invalid"
					" AnswerOriginKind value");
			goto error;
		}

		py_o = _pyccn_Int_FromLong(r);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_Interest, "answerOriginKind", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	//        self.scope  = None
	len = pi->offset[CCN_PI_E_Scope] - pi->offset[CCN_PI_B_Scope];
	if (len > 0) {
		r = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_Scope, interest->buf,
				pi->offset[CCN_PI_B_Scope], pi->offset[CCN_PI_E_Scope]);
		if (r < 0) {
			PyErr_SetString(g_PyExc_CCNInterestError, "Invalid"
					" Scope value");
			goto error;
		}

		py_o = _pyccn_Int_FromLong(r);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_Interest, "scope", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	//        self.interestLifetime = None
	len = pi->offset[CCN_PI_E_InterestLifetime] -
			pi->offset[CCN_PI_B_InterestLifetime];
	if (len > 0) {
		double lifetime;

		// From packet-ccn.c
		r = ccn_ref_tagged_BLOB(CCN_DTAG_InterestLifetime, interest->buf,
				pi->offset[CCN_PI_B_InterestLifetime],
				pi->offset[CCN_PI_E_InterestLifetime], &blob, &blob_size);
		if (r < 0) {
			PyErr_SetString(g_PyExc_CCNInterestError, "Invalid"
					" InterestLifetime value");
			goto error;
		}

		/* XXX: probably won't work with bigendian */
		lifetime = 0.0;
		for (size_t i = 0; i < blob_size; i++)
			lifetime = lifetime * 256.0 + (double) blob[i];
		lifetime /= 4096.0;

		py_o = PyFloat_FromDouble(lifetime);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_Interest, "interestLifetime", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	//        self.nonce = None
	len = pi->offset[CCN_PI_E_Nonce] - pi->offset[CCN_PI_B_Nonce];
	if (len > 0) {
		r = ccn_ref_tagged_BLOB(CCN_DTAG_Nonce, interest->buf,
				pi->offset[CCN_PI_B_Nonce], pi->offset[CCN_PI_E_Nonce], &blob,
				&blob_size);
		if (r < 0) {
			PyErr_SetString(g_PyExc_CCNInterestError, "Invalid"
					" Nonce value");
			goto error;
		}

		py_o = PyBytes_FromStringAndSize((const char *) blob, blob_size);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_Interest, "nonce", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	r = PyObject_SetAttrString(py_obj_Interest, "ccn_data_dirty", Py_False);
	JUMP_IF_NEG(r, error);

	// 4) Return the created object
	debug("Interest_from_ccn ends\n");

	return py_obj_Interest;

error:
	Py_DECREF(py_obj_Interest);

	return NULL;
}

struct ccn_parsed_interest *
_pyccn_interest_get_pi(PyObject *py_interest)
{
	struct interest_data *context;
	struct ccn_charbuf *interest;
	int r;

	assert(CCNObject_IsValid(INTEREST, py_interest));

	context = PyCapsule_GetContext(py_interest);
	assert(context);

	if (context->pi)
		return context->pi;

	interest = CCNObject_Get(INTEREST, py_interest);

	context->pi = calloc(1, sizeof(struct ccn_parsed_interest));
	JUMP_IF_NULL_MEM(context->pi, error);

	/* TODO: we should also use the comps argument */
	r = ccn_parse_interest(interest->buf, interest->length, context->pi, NULL);
	if (r < 0) {
		PyErr_SetString(g_PyExc_CCNInterestError, "Unable to parse the"
				" Interest");
		goto error;
	}

	assert(context->pi);
	return context->pi;

error:
	return NULL;

}

void
_pyccn_interest_set_pi(PyObject *py_interest, struct ccn_parsed_interest *pi)
{
	struct interest_data *context;

	assert(CCNObject_IsValid(INTEREST, py_interest));

	context = PyCapsule_GetContext(py_interest);
	assert(context);

	if (context->pi)
		free(context->pi);
	context->pi = pi;
}

/*
 * From within python
 */

PyObject *
_pyccn_cmd_Interest_obj_to_ccn(PyObject *UNUSED(self), PyObject *py_obj_Interest)
{
	if (strcmp(py_obj_Interest->ob_type->tp_name, "Interest") != 0) {
		PyErr_SetString(PyExc_TypeError, "Must pass an Interest");
		return NULL;
	}

	return Interest_obj_to_ccn(py_obj_Interest);
}

PyObject *
_pyccn_cmd_Interest_obj_from_ccn(PyObject *UNUSED(self), PyObject *py_interest)
{
	if (!CCNObject_IsValid(INTEREST, py_interest)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Interest as 1st"
				" argument");
		return NULL;
	}

	return Interest_obj_from_ccn(py_interest);
}

PyObject *
_pyccn_cmd_ExclusionFilter_names_to_ccn(PyObject *UNUSED(self), PyObject *py_names)
{
	if (!PyList_Check(py_names)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a list of CCN names");
		return NULL;
	}

	return ExclusionFilter_names_to_ccn(py_names);
}

PyObject *
_pyccn_cmd_ExclusionFilter_obj_from_ccn(PyObject *UNUSED(self),
		PyObject *py_exclusion_filter)
{
	if (!CCNObject_IsValid(EXCLUSION_FILTER, py_exclusion_filter)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Exclusion Filter");
		return NULL;
	}

	return ExclusionFilter_obj_from_ccn(py_exclusion_filter);
}
