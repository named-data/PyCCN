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
#include "methods_signedinfo.h"
#include "misc.h"
#include "objects.h"

// IMPLEMENTATION OF OBJECT CONVERTERS,
// TO AND FROM CCNx LIBRARY STRUCTURES OR
// FROM THE WIRE FORMAT, IF THERE ARE NO
// CORRESPONDING C STRUCTS.


// From within python
//
//TODO: Check cobjecttype




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

	assert(0); //TODO: we need to pass PyObject not struct charbuf*
	if (signing_params->template_ccnb != NULL)
		if (signing_params->template_ccnb->length > 0)
			p = SignedInfo_obj_from_ccn(signing_params->template_ccnb);
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
