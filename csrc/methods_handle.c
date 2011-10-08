/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#include "python_hdr.h"
#include <ccn/ccn.h>
#include <ccn/ccn_private.h>
#include <ccn/keystore.h>
#include <ccn/reg_mgmt.h>

#include "pyccn.h"
#include "util.h"
#include "key_utils.h"
#include "methods_contentobject.h"
#include "methods_handle.h"
#include "methods_interest.h"
#include "methods_key.h"
#include "objects.h"

static PyObject *
UpcallInfo_obj_from_ccn(enum ccn_upcall_kind upcall_kind,
		struct ccn_upcall_info *ui)
{
	PyObject *py_obj_UpcallInfo;
	PyObject *py_o;
	PyObject *py_data = NULL;
	struct ccn_charbuf *data;
	int r;

	assert(g_type_UpcallInfo);

	// Create name object
	py_obj_UpcallInfo = PyObject_CallObject(g_type_UpcallInfo, NULL);
	JUMP_IF_NULL(py_obj_UpcallInfo, error);

#if 0
	// CCN handle, I hope it isn't freed; if it is freed we'll get a crash :/
	py_o = CCNObject_Borrow(HANDLE, ui->h);
	r = PyObject_SetAttrString(py_obj_UpcallInfo, "ccn", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NEG(r, error);
#endif

	py_o = _pyccn_Int_FromLong(ui->matched_comps);
	r = PyObject_SetAttrString(py_obj_UpcallInfo, "matchedComps", py_o);
	Py_DECREF(py_o);
	JUMP_IF_NULL(py_o, error);

	if (upcall_kind == CCN_UPCALL_CONTENT ||
			upcall_kind == CCN_UPCALL_CONTENT_UNVERIFIED ||
			upcall_kind == CCN_UPCALL_CONTENT_BAD) {

		py_data = CCNObject_New_charbuf(CONTENT_OBJECT, &data);
		JUMP_IF_NULL(py_data, error);
		r = ccn_charbuf_append(data, ui->content_ccnb,
				ui->pco->offset[CCN_PCO_E]);
		JUMP_IF_NEG_MEM(r, error);

		py_o = ContentObject_obj_from_ccn(py_data);
		Py_CLEAR(py_data);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_UpcallInfo, "ContentObject", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	if (upcall_kind == CCN_UPCALL_INTEREST ||
			upcall_kind == CCN_UPCALL_CONSUMED_INTEREST ||
			upcall_kind == CCN_UPCALL_CONTENT ||
			upcall_kind == CCN_UPCALL_INTEREST_TIMED_OUT ||
			upcall_kind == CCN_UPCALL_CONTENT_UNVERIFIED ||
			upcall_kind == CCN_UPCALL_CONTENT_BAD) {
		py_data = CCNObject_New_charbuf(INTEREST, &data);
		JUMP_IF_NULL(py_data, error);
		r = ccn_charbuf_append(data, ui->interest_ccnb,
				ui->pi->offset[CCN_PI_E]);
		JUMP_IF_NEG_MEM(r, error);

		py_o = Interest_obj_from_ccn(py_data);
		Py_CLEAR(py_data);
		JUMP_IF_NULL(py_o, error);

		r = PyObject_SetAttrString(py_obj_UpcallInfo, "Interest", py_o);
		Py_DECREF(py_o);
		JUMP_IF_NEG(r, error);
	}

	return py_obj_UpcallInfo;

error:
	Py_XDECREF(py_data);
	Py_XDECREF(py_obj_UpcallInfo);
	return NULL;
}

static enum ccn_upcall_res
ccn_upcall_handler(struct ccn_closure *selfp,
		enum ccn_upcall_kind upcall_kind,
		struct ccn_upcall_info *info)
{
	PyObject *upcall_method = NULL, *py_upcall_info = NULL;
	PyObject *py_selfp, *py_closure, *arglist, *result;
	PyGILState_STATE gstate;

	debug("upcall_handler dispatched kind %d\n", upcall_kind);

	assert(selfp);
	assert(selfp->data);

	gstate = PyGILState_Ensure();

	/* equivalent of selfp, wrapped into PyCapsule */
	py_selfp = selfp->data;
	py_closure = PyCapsule_GetContext(py_selfp);
	assert(py_closure);

	upcall_method = PyObject_GetAttrString(py_closure, "upcall");
	JUMP_IF_NULL(upcall_method, error);

	debug("Generating UpcallInfo\n");
	py_upcall_info = UpcallInfo_obj_from_ccn(upcall_kind, info);
	JUMP_IF_NULL(py_upcall_info, error);
	debug("Done generating UpcallInfo\n");

	arglist = Py_BuildValue("iO", upcall_kind, py_upcall_info);
	Py_CLEAR(py_upcall_info);

	debug("Calling upcall\n");

	result = PyObject_CallObject(upcall_method, arglist);

	Py_CLEAR(upcall_method);
	Py_DECREF(arglist);
	JUMP_IF_NULL(result, error);

	if (upcall_kind == CCN_UPCALL_FINAL)
		Py_DECREF(py_selfp);

	long r = _pyccn_Int_AsLong(result);

	PyGILState_Release(gstate);

	return r;

error:
	debug("Error routine called (upcall_kind = %d)\n", upcall_kind);
	if (upcall_kind == CCN_UPCALL_FINAL)
		Py_DECREF(py_selfp);
	Py_XDECREF(py_upcall_info);
	Py_XDECREF(upcall_method);

	//XXX: I hope this is the correct way to handle exceptions thrown
	if (PyErr_Occurred())
		PyErr_Print();

	PyGILState_Release(gstate);
	return CCN_UPCALL_RESULT_ERR;
}

PyObject *
_pyccn_cmd_is_run_executing(PyObject *UNUSED(self), PyObject *py_handle)
{
	struct ccn *handle;
	PyObject *res;

	if (!CCNObject_IsValid(HANDLE, py_handle)) {
		PyErr_SetString(PyExc_TypeError, "Expected CCN handle");
		return NULL;
	}
	handle = CCNObject_Get(HANDLE, py_handle);

	res = _pyccn_run_state_find(handle) ? Py_True : Py_False;

	return Py_INCREF(res), res;
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

PyObject *
_pyccn_cmd_create(PyObject *UNUSED(self), PyObject *UNUSED(args))
{
	struct ccn *ccn_handle = ccn_create();

	if (!ccn_handle) {
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

PyObject *
_pyccn_cmd_connect(PyObject *UNUSED(self), PyObject *py_ccn_handle)
{
	struct ccn *handle;
	int r;

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

PyObject *
_pyccn_cmd_disconnect(PyObject *UNUSED(self), PyObject *py_ccn_handle)
{
	struct ccn *handle;
	int r;

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

PyObject *
_pyccn_get_connection_fd(PyObject *UNUSED(self), PyObject *py_handle)
{
	struct ccn *handle;

	if (!CCNObject_IsValid(HANDLE, py_handle)) {
		PyErr_SetString(PyExc_TypeError, "Expected CCN handle");
		return NULL;
	}

	handle = CCNObject_Get(HANDLE, py_handle);

	return Py_BuildValue("i", ccn_get_connection_fd(handle));
}

PyObject *
_pyccn_cmd_process_scheduled_operations(PyObject *UNUSED(self), PyObject *py_handle)
{
	struct ccn *handle;

	if (!CCNObject_IsValid(HANDLE, py_handle)) {
		PyErr_SetString(PyExc_TypeError, "Expected CCN handle");
		return NULL;
	}

	handle = CCNObject_Get(HANDLE, py_handle);

	return Py_BuildValue("i", ccn_process_scheduled_operations(handle));
}

PyObject *
_pyccn_cmd_output_is_pending(PyObject *UNUSED(self), PyObject *py_handle)
{
	struct ccn *handle;
	PyObject *res;

	if (!CCNObject_IsValid(HANDLE, py_handle)) {
		PyErr_SetString(PyExc_TypeError, "Expected CCN handle");
		return NULL;
	}

	handle = CCNObject_Get(HANDLE, py_handle);

	res = ccn_output_is_pending(handle) ? Py_True : Py_False;

	return Py_INCREF(res), res;
}

PyObject *
_pyccn_cmd_run(PyObject *UNUSED(self), PyObject *args)
{
	int r;
	PyObject *py_handle;
	int timeoutms = -1;
	struct ccn *handle;
	void *state_slot;

	if (!PyArg_ParseTuple(args, "O|i", &py_handle, &timeoutms))
		return NULL;

	if (!CCNObject_IsValid(HANDLE, py_handle)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Handle");
		return NULL;
	}
	handle = CCNObject_Get(HANDLE, py_handle);

	state_slot = _pyccn_run_state_add(handle);
	if (!state_slot)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	debug("Entering ccn_run()\n");
	r = ccn_run(handle, timeoutms);
	debug("Exited ccn_run()\n");
	Py_END_ALLOW_THREADS

	_pyccn_run_state_clear(state_slot);

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

PyObject *
_pyccn_cmd_set_run_timeout(PyObject *UNUSED(self), PyObject *args)
{
	int r;
	PyObject *py_handle;
	int timeoutms = 0;
	struct ccn *handle;

	if (!PyArg_ParseTuple(args, "O|i", &py_handle, &timeoutms))
		return NULL;

	if (!CCNObject_IsValid(HANDLE, py_handle)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN handle");
		return NULL;
	}
	handle = CCNObject_Get(HANDLE, py_handle);

	r = ccn_set_run_timeout(handle, timeoutms);

	return Py_BuildValue("i", r);
}

PyObject *
_pyccn_cmd_express_interest(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_o, *py_ccn, *py_name, *py_closure, *py_templ;
	int r;
	struct ccn *handle;
	struct ccn_charbuf *name, *templ;
	struct ccn_closure *cl;

	if (!PyArg_ParseTuple(args, "OOOO", &py_ccn, &py_name, &py_closure,
			&py_templ))
		return NULL;

	if (strcmp(py_ccn->ob_type->tp_name, "CCN")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a ccn as arg 1");
		return NULL;
	}
	if (strcmp(py_name->ob_type->tp_name, "Name")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Name as arg 2");
		return NULL;
	}

	/* I think we should use this to do type checks -- Derek */
	if (!PyObject_IsInstance(py_closure, g_type_Closure)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Closure as arg 3");
		return NULL;
	}

	if (py_templ != Py_None && strcmp(py_templ->ob_type->tp_name, "Interest")) {
		PyErr_SetString(PyExc_TypeError, "Must pass an Interest as arg 4");
		return NULL;
	}

	// Dereference the CCN handle, name, and template

	py_o = PyObject_GetAttrString(py_ccn, "ccn_data");
	if (!py_o)
		return NULL;
	handle = CCNObject_Get(HANDLE, py_o);
	Py_DECREF(py_o);

	py_o = PyObject_GetAttrString(py_name, "ccn_data");
	if (!py_o)
		return NULL;
	name = CCNObject_Get(NAME, py_o);
	Py_DECREF(py_o);

	if (py_templ != Py_None) {
		py_o = PyObject_GetAttrString(py_templ, "ccn_data");
		if (!py_o)
			return NULL;
		Py_DECREF(py_o);
		templ = CCNObject_Get(INTEREST, py_o);
	} else
		templ = NULL;

	// Build the closure
	py_o = CCNObject_New_Closure(&cl);
	cl->p = ccn_upcall_handler;
	cl->data = py_o;
	Py_INCREF(py_closure); /* We don't want py_closure to be dealocated */
	r = PyCapsule_SetContext(py_o, py_closure);
	assert(r == 0);

	/* I don't think Closure needs this, the information is only valid
	 * for time the interest is issued, it would also complicate things
	 * if the same closure would be used multiple times -- Derek
	 */
#if 0
	PyObject_SetAttrString(py_closure, "ccn_data", py_o);
	PyObject_GC_Track(py_o); //Add object to cyclic garbage collector
	PyObject_GC_Track(py_closure);
#endif

	r = ccn_express_interest(handle, name, cl, templ);
	if (r < 0) {
		int err = ccn_geterror(handle);

		Py_DECREF(py_o);
		PyErr_Format(PyExc_IOError, "Unable to issue an interest: %s [%d]",
				strerror(err), err);
		return NULL;
	}

	/*
	 * We aren't decreasing reference to py_o, because we're expecting
	 * to ccn call our hook where we will do it
	 */

	Py_RETURN_NONE;
}

PyObject *
_pyccn_cmd_set_interest_filter(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_ccn, *py_name, *py_closure, *py_o;
	int forw_flags = CCN_FORW_ACTIVE | CCN_FORW_CHILD_INHERIT;
	struct ccn *handle;
	struct ccn_charbuf *name;
	struct ccn_closure *closure;
	int r;

	if (!PyArg_ParseTuple(args, "OOO|i", &py_ccn, &py_name, &py_closure,
			&forw_flags))
		return NULL;

	if (!CCNObject_IsValid(HANDLE, py_ccn)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN handle as arg 1");
		return NULL;
	}

	if (!CCNObject_IsValid(NAME, py_name)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Name as arg 1");
		return NULL;
	}

	if (!PyObject_IsInstance(py_closure, g_type_Closure)) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN Closure as arg 3");
		return NULL;
	}

	handle = CCNObject_Get(HANDLE, py_ccn);
	name = CCNObject_Get(NAME, py_name);

	/*
	 * This code it might be confusing so here is what it does:
	 * 1. we allocate a closure structure and wrap it into PyCapsule, so we can
	 *    easily do garbage collection. Decreasing reference count will
	 *    deallocate everything
	 * 2. set our closure handler
	 * 3. set pointer to our capsule (that way when callback is triggered we
	 *    have access to Python closure object)
	 * 4. increase reference count for Closure object to make sure someone
	 *    won't free it
	 * 5. we add pointer for our closure class (so we can call correct method)
	 */
	py_o = CCNObject_New_Closure(&closure);
	closure->p = ccn_upcall_handler;
	closure->data = py_o;
	Py_INCREF(py_closure);
	r = PyCapsule_SetContext(py_o, py_closure);
	assert(r == 0);

	r = ccn_set_interest_filter_with_flags(handle, name, closure, forw_flags);
	if (r < 0) {
		int err = ccn_geterror(handle);

		Py_DECREF(py_o);
		PyErr_Format(PyExc_IOError, "Unable to set and interest filter: %s [%d]",
				strerror(err), err);
		return NULL;
	}

	return Py_BuildValue("i", r);
}

// Simple get/put

PyObject *
_pyccn_cmd_get(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_CCN, *py_Name, *py_Interest = Py_None;
	PyObject *py_co = NULL, *py_o = NULL;
	PyObject *py_data = NULL;
	int r, timeout = 3000;
	struct ccn *handle;
	struct ccn_charbuf *name, *interest, *data;
	struct ccn_parsed_ContentObject *pco;
	struct ccn_indexbuf *comps;

	if (!PyArg_ParseTuple(args, "OO|Oi", &py_CCN, &py_Name, &py_Interest,
			&timeout))
		return NULL;

	if (strcmp(py_CCN->ob_type->tp_name, "CCN")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN as arg 1");
		return NULL;
	} else {
		py_o = PyObject_GetAttrString(py_CCN, "ccn_data");
		JUMP_IF_NULL(py_o, exit);
		handle = CCNObject_Get(HANDLE, py_o);
		JUMP_IF_NULL(handle, exit);
		Py_CLEAR(py_o);
	}

	if (strcmp(py_Name->ob_type->tp_name, "Name")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a Name as arg 2");
		return NULL;
	} else {
		py_o = PyObject_GetAttrString(py_Name, "ccn_data");
		JUMP_IF_NULL(py_o, exit);
		name = CCNObject_Get(NAME, py_o);
		JUMP_IF_NULL(name, exit);
		Py_CLEAR(py_o);
	}

	assert(py_Interest);
	if (py_Interest != Py_None && strcmp(py_Interest->ob_type->tp_name, "Interest")) {
		PyErr_SetString(PyExc_TypeError, "Must pass an Interest as arg 3");
		return NULL;
	} else if (py_Interest == Py_None)
		interest = NULL;
	else {
		py_o = PyObject_GetAttrString(py_Interest, "ccn_data");
		JUMP_IF_NULL(py_o, exit);
		interest = CCNObject_Get(INTEREST, py_o);
		JUMP_IF_NULL(interest, exit);
		Py_CLEAR(py_o);
	}

	py_data = CCNObject_New_charbuf(CONTENT_OBJECT, &data);
	JUMP_IF_NULL(py_data, exit);
	pco = calloc(1, sizeof(*pco));
	_pyccn_content_object_set_pco(py_data, pco);
	JUMP_IF_NULL_MEM(pco, exit);
	comps = ccn_indexbuf_create();
	_pyccn_content_object_set_comps(py_data, comps);
	JUMP_IF_NULL_MEM(comps, exit);

	Py_BEGIN_ALLOW_THREADS
	r = ccn_get(handle, name, interest, timeout, data, pco, comps, 0);
	Py_END_ALLOW_THREADS

	debug("ccn_get result=%d\n", r);

	if (r < 0) {
		//CCN doesn't clearly say when timeout happens, we're assuming
		//it is when no error was set
		int err = ccn_geterror(handle);
		if (err)
			py_co = PyErr_Format(PyExc_IOError, "%s [%d]", strerror(err), err);
		else
			py_co = (Py_INCREF(Py_None), Py_None); // timeout
	} else
		py_co = ContentObject_obj_from_ccn(py_data);

exit:
	Py_XDECREF(py_data);
	Py_XDECREF(py_o);
	return py_co;
}

PyObject * // int
_pyccn_cmd_put(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_ccn, *py_content_object;
	PyObject *py_o;
	struct ccn_charbuf *content_object;
	struct ccn *handle;
	int r;

	if (!PyArg_ParseTuple(args, "OO", &py_ccn, &py_content_object))
		return NULL;

	if (strcmp(py_ccn->ob_type->tp_name, "CCN")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a CCN as arg 1");
		return NULL;
	}
	if (strcmp(py_content_object->ob_type->tp_name, "ContentObject")) {
		PyErr_SetString(PyExc_TypeError, "Must pass a ContentObject as arg 2");
		return NULL;
	}

	py_o = PyObject_GetAttrString(py_ccn, "ccn_data");
	JUMP_IF_NULL(py_o, error);

	handle = CCNObject_Get(HANDLE, py_o);
	Py_DECREF(py_o);
	assert(handle);

	py_o = PyObject_GetAttrString(py_content_object, "ccn_data");
	JUMP_IF_NULL(py_o, error);

	content_object = CCNObject_Get(CONTENT_OBJECT, py_o);
	Py_DECREF(py_o);
	assert(content_object);

	r = ccn_put(handle, content_object->buf, content_object->length);
	if (r < 0) {
		int err = ccn_geterror(handle);
		return PyErr_Format(PyExc_IOError, "%s [%d]", strerror(err), err);
	}

	return Py_BuildValue("i", r);

error:
	return NULL;
}

PyObject *
_pyccn_cmd_get_default_key(PyObject *UNUSED(self), PyObject *UNUSED(arg))
{
	struct ccn_keystore *keystore = NULL;
	struct ccn_charbuf *buf = NULL;
	const struct ccn_pkey *key;
	int r;
	PyObject *py_ccn_key, *py_Key_obj;

	buf = ccn_charbuf_create();
	JUMP_IF_NULL_MEM(buf, error);

	r = ccn_charbuf_putf(buf, "%s/.ccnx/.ccnx_keystore", getenv("HOME"));
	JUMP_IF_NEG_MEM(r, error);

	keystore = ccn_keystore_create();
	JUMP_IF_NULL_MEM(keystore, error);

	r = ccn_keystore_init(keystore, ccn_charbuf_as_string(buf),
			"Th1s1sn0t8g00dp8ssw0rd.");
	ccn_charbuf_destroy(&buf);
	if (r < 0) {
		PyErr_Format(g_PyExc_CCNError, "Failed to initialize keystore (%d)", r);
		goto error;
	}

	key = ccn_keystore_private_key(keystore);
	assert(key);

	py_ccn_key = _pyccn_privatekey_dup(key);
	JUMP_IF_NULL(py_ccn_key, error);

	py_Key_obj = Key_obj_from_ccn(py_ccn_key);
	Py_DECREF(py_ccn_key);
	ccn_keystore_destroy(&keystore);

	return py_Key_obj;

error:
	ccn_keystore_destroy(&keystore);
	ccn_charbuf_destroy(&buf);
	return NULL;
}
