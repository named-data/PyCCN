/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 */

#include <python_hdr.h>

#include <ccn/ccn.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "namecrypto/authentication.h"

#include "pyccn.h"
#include "util.h"
#include "methods_namecrypto.h"
#include "objects.h"

//return 1 - yes
//return 0 - no

static int
verify_policy(unsigned char *UNUSED(appname), int UNUSED(appname_length))
{
	return 1;
}

PyObject *
_pyccn_cmd_nc_new_state(PyObject *UNUSED(self), PyObject *UNUSED(args))
{
	state *new_state;
	PyObject *py_new_state;

	new_state = malloc(sizeof(*new_state));
	JUMP_IF_NULL_MEM(new_state, error);

	state_init(new_state);

	py_new_state = CCNObject_New(NAMECRYPTO_STATE, new_state);
	if (!py_new_state) {
		free(new_state);
		goto error;
	}

	return py_new_state;

error:
	return NULL;
}

PyObject *
_pyccn_cmd_nc_authenticate_command(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_state, *py_name, *py_appname, *py_appkey;
	PyObject *py_new_name;
	state *auth_state;
	struct ccn_charbuf *name, *new_name;
	unsigned char *appname, *appkey;
	Py_ssize_t appname_len, appkey_len;
	int r;

	if (!PyArg_ParseTuple(args, "OOOO", &py_state, &py_name, &py_appname,
			&py_appkey))
		return NULL;

	if (!CCNObject_ReqType(NAMECRYPTO_STATE, py_state))
		return NULL;

	if (!CCNObject_ReqType(NAME, py_name))
		return NULL;

	auth_state = CCNObject_Get(NAMECRYPTO_STATE, py_state);
	name = CCNObject_Get(NAME, py_name);

	if (PyBytes_AsStringAndSize(py_appname, (char **) &appname, &appname_len) < 0)
		return NULL;

	if (PyBytes_AsStringAndSize(py_appkey, (char **) &appkey, &appkey_len) < 0)
		return NULL;

	if (appkey_len != APPKEYLEN) {
		PyErr_Format(PyExc_ValueError, "key length needs to be %d bytes long",
				APPKEYLEN);
		return NULL;
	}

	py_new_name = CCNObject_New_charbuf(NAME, &new_name);
	JUMP_IF_NULL(py_new_name, error);

	r = ccn_charbuf_append_charbuf(new_name, name);
	if (r < 0)
		Py_DECREF(py_new_name);
	JUMP_IF_NEG_MEM(r, error);

	authenticateCommand(auth_state, new_name, appname, appname_len, appkey);

	return py_new_name;

error:
	return NULL;
}

PyObject *
_pyccn_cmd_nc_authenticate_command_sig(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_state, *py_name, *py_appname, *py_sigkey;
	PyObject *py_new_name;
	state *auth_state;
	struct ccn_charbuf *name, *new_name;
	unsigned char *appname;
	Py_ssize_t appname_len;
	struct ccn_pkey *priv_key;
	RSA *rsa_priv_key;
	int r;
	unsigned long err;

	if (!PyArg_ParseTuple(args, "OOOO", &py_state, &py_name, &py_appname,
			&py_sigkey))
		return NULL;

	if (!CCNObject_ReqType(NAMECRYPTO_STATE, py_state))
		return NULL;

	if (!CCNObject_ReqType(NAME, py_name))
		return NULL;

	auth_state = CCNObject_Get(NAMECRYPTO_STATE, py_state);
	name = CCNObject_Get(NAME, py_name);

	if (PyBytes_AsStringAndSize(py_appname, (char **) &appname, &appname_len) < 0)
		return NULL;

	if (!CCNObject_ReqType(PKEY_PRIV, py_sigkey))
		return NULL;

	priv_key = CCNObject_Get(PKEY_PRIV, py_sigkey);

	py_new_name = CCNObject_New_charbuf(NAME, &new_name);
	JUMP_IF_NULL(py_new_name, error);

	r = ccn_charbuf_append_charbuf(new_name, name);
	if (r < 0)
		Py_DECREF(py_new_name);
	JUMP_IF_NEG_MEM(r, error);

	rsa_priv_key = EVP_PKEY_get1_RSA((EVP_PKEY *) priv_key);
	JUMP_IF_NULL(rsa_priv_key, openssl_error);
	authenticateCommandSig(auth_state, new_name, appname, appname_len,
			rsa_priv_key);
	RSA_free(rsa_priv_key);

	return py_new_name;

openssl_error:
	err = ERR_get_error();
	PyErr_Format(g_PyExc_CCNKeyError, "Unable to convert given key to RSA: %s",
			ERR_reason_error_string(err));
error:
	return NULL;
}

PyObject *
_pyccn_cmd_nc_verify_command(PyObject *UNUSED(self), PyObject *args,
		PyObject *kwds)
{
	PyObject *py_auth_state, *py_name;
	unsigned long maxtime_ms;
	state *auth_state;
	struct ccn_charbuf *name;
	PyObject *py_fixture_key = Py_None, *py_pub_key = Py_None,
			*py_policy = Py_None;
	unsigned char *fixture_key;
	Py_ssize_t fixture_key_len;
	struct ccn_pkey *pub_key;
	RSA *rsa_pub_key;
	int r;
	unsigned long err;

	static char *kwlist[] = {"state", "name", "maxdiff_ms", "fixture_key",
		"pub_key", "policy", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOk|OOO", kwlist,
			&py_auth_state, &py_name, &maxtime_ms, &py_fixture_key, &py_pub_key,
			&py_policy))
		return NULL;

	if (!CCNObject_ReqType(NAMECRYPTO_STATE, py_auth_state))
		return NULL;

	if (!CCNObject_ReqType(NAME, py_name))
		return NULL;

	auth_state = CCNObject_Get(NAMECRYPTO_STATE, py_auth_state);
	name = CCNObject_Get(NAME, py_name);

	if (py_fixture_key != Py_None) {
		if (PyBytes_AsStringAndSize(py_fixture_key, (char **) &fixture_key,
				&fixture_key_len) < 0)
			return NULL;
	} else {
		fixture_key = NULL;
		fixture_key_len = 0;
	}

	if (py_pub_key != Py_None) {
		if (!CCNObject_ReqType(PKEY_PUB, py_pub_key))
			return NULL;
		pub_key = CCNObject_Get(PKEY_PUB, py_pub_key);
		rsa_pub_key = EVP_PKEY_get1_RSA((EVP_PKEY *) pub_key);
		JUMP_IF_NULL(rsa_pub_key, openssl_error);
	} else
		rsa_pub_key = NULL;

	//TODO: handle policy

	r = verifyCommand(name, fixture_key, fixture_key_len, rsa_pub_key,
			auth_state, maxtime_ms, verify_policy);

	if (py_pub_key != Py_None)
		RSA_free(rsa_pub_key);

	if (r == AUTH_OK)
		Py_RETURN_TRUE;

	return Py_BuildValue("i", r);

openssl_error:
	err = ERR_get_error();
	PyErr_Format(g_PyExc_CCNKeyError, "Unable to convert given key to RSA: %s",
			ERR_reason_error_string(err));
	return NULL;
}

PyObject *
_pyccn_cmd_nc_app_id(PyObject *UNUSED(self), PyObject *py_appname)
{
	unsigned char appid[APPIDLEN];
	unsigned char *appname, *ret;
	Py_ssize_t appname_len;
	int r;

	r = PyBytes_AsStringAndSize(py_appname, (char **) &appname, &appname_len);
	if (r < 0)
		return NULL;

	ret = appID(appname, appname_len, appid);
	if (!ret) {
		PyErr_NoMemory();
		return NULL;
	}

#if PY_MAJOR_VERSION >= 3
	return Py_BuildValue("y#", appid, APPIDLEN);
#else
	return Py_BuildValue("s#", appid, APPIDLEN);
#endif
}

PyObject *
_pyccn_cmd_nc_app_key(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_fixture_key, *py_appid, *py_policy;
	unsigned char *fixture_key, *appid, *policy, *res;
	Py_ssize_t fixture_key_len, appid_len, policy_len;
	unsigned char appkey[APPKEYLEN];

	if (!PyArg_ParseTuple(args, "OOO", &py_fixture_key, &py_appid, &py_policy))
		return NULL;

	if (PyBytes_AsStringAndSize(py_fixture_key, (char **) &fixture_key,
			&fixture_key_len) < 0)
		return NULL;

	if (PyBytes_AsStringAndSize(py_appid, (char **) &appid, &appid_len) < 0)
		return NULL;

	if (appid_len != APPIDLEN) {
		PyErr_Format(PyExc_ValueError, "appid needs to be %zd bytes long",
				APPIDLEN);
		return NULL;
	}

	if (PyBytes_AsStringAndSize(py_policy, (char **) &policy, &policy_len) < 0)
		return NULL;

	res = appKey(fixture_key, fixture_key_len, appid, policy, policy_len,
			appkey);
	if (!res) {
		PyErr_NoMemory();
		return NULL;
	}

#if PY_MAJOR_VERSION >= 3
	return Py_BuildValue("y#", appkey, APPKEYLEN);
#else
	return Py_BuildValue("s#", appkey, APPKEYLEN);
#endif
}

PyObject *
_pyccn_cmd_nc_build_first_authenticator(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_initial_authenticator, *py_encrypted_info, *py_unencrypted_info;
	unsigned char *initial_authenticator, *encrypted_info, *unencrypted_info;
	int initial_authenticator_len, encrypted_info_len,
			unencrypted_info_len;

	unsigned char *authenticator_token;
	int authenticator_token_len;
	PyObject *py_r;

	if (!PyArg_ParseTuple(args, "SSS", &py_initial_authenticator,
			&py_encrypted_info, &py_unencrypted_info))
		return NULL;


	if (PyBytes_AsStringAndSize(py_initial_authenticator,
			(char **) &initial_authenticator, &initial_authenticator_len) < 0)
		return NULL;

	if (PyBytes_AsStringAndSize(py_encrypted_info, (char **) &encrypted_info,
			&encrypted_info_len) < 0)
		return NULL;

	if (PyBytes_AsStringAndSize(py_unencrypted_info, (char **) &unencrypted_info,
			&unencrypted_info_len) < 0)
		return NULL;

	authenticator_token_len = buildFirstAuthenticator(initial_authenticator,
			initial_authenticator_len, encrypted_info, encrypted_info_len,
			unencrypted_info, unencrypted_info_len, &authenticator_token);
	if (authenticator_token_len < 0)
		return PyErr_NoMemory();

	assert(authenticator_token);
	py_r = PyBytes_FromStringAndSize((char *) authenticator_token,
			authenticator_token_len);
	free(authenticator_token);

	return py_r;
}

PyObject *
_pyccn_cmd_nc_verify_first_authenticator(PyObject *UNUSED(self), PyObject *args)
{
	PyObject *py_initial_authenticator, *py_authenticator_token;
	unsigned char *initial_authenticator, *authenticator_token;
	int initial_authenticator_len, authenticator_token_len;
	unsigned char *encrypted_info, *unencrypted_info;
	unsigned int encrypted_info_len, unencrypted_info_len;
	int rc;
	PyObject *py_ret;

	if (!PyArg_ParseTuple(args, "SS", &py_initial_authenticator,
			&py_authenticator_token))
		return NULL;

	if (PyBytes_AsStringAndSize(py_initial_authenticator,
			(char **) &initial_authenticator, &initial_authenticator_len) < 0)
		return NULL;

	if (PyBytes_AsStringAndSize(py_authenticator_token,
			(char **) &authenticator_token, &authenticator_token_len) < 0)
		return NULL;

	rc = verifyFirstAuthenticator(initial_authenticator,
			initial_authenticator_len, authenticator_token,
			authenticator_token_len, &encrypted_info, &encrypted_info_len,
			&unencrypted_info, &unencrypted_info_len);
	if (rc == FAIL_NO_MEMORY)
		return PyErr_NoMemory();
	if (rc < 0)
		return PyErr_Format(PyExc_Exception, "verifyFirstAuthenticator failed"
			" with err %d (%s)", rc, retToString(rc));

#if PY_MAJOR_VERSION >= 3
	py_ret = Py_BuildValue("(y#,y#)", encrypted_info, encrypted_info_len,
			unencrypted_info, unencrypted_info_len);
#else
	py_ret = Py_BuildValue("(s#,s#)", encrypted_info, encrypted_info_len,
			unencrypted_info, unencrypted_info_len);
#endif
	free(encrypted_info);
	free(unencrypted_info);

	return py_ret;
}