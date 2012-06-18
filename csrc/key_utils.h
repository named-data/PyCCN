/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#ifndef _KEY_UTILS_H_
#  define _KEY_UTILS_H_

// Load these here to make it easier on the app

// On MacOS X, need to have the latest version from MacPorts
// and add /opt/local/include as an include path
#  include <openssl/rsa.h>
#  include <openssl/pem.h>
#  include <openssl/evp.h>
#  include <openssl/sha.h>
#  include <openssl/ossl_typ.h>

#  include <ccn/keystore.h>

// work with CCN_pkey structures directly
//

// This is a lot like ccn's keystore, but
// that is an opaque type, so we're not supposed
// to use it directly.

struct keypair {
	struct ccn_pkey* private_key;
	struct ccn_pkey* public_key;
	unsigned char* public_key_digest;
	size_t public_key_digest_len;
};

void initialize_crypto(void);
int create_public_key_digest(RSA *private_key_rsa,
		PyObject **py_public_key_digest, int *public_key_digest_len);
int ccn_keypair_from_rsa(int public_only, RSA *private_key_rsa,
		PyObject **py_private_key_ccn,
		PyObject **py_public_key_ccn);
PyObject *_pyccn_privatekey_dup(const struct ccn_pkey *key);
int generate_key(int length, PyObject **private_key_ccn,
		PyObject **public_key_ccn, PyObject ** public_key_digest,
		int *public_key_digest_len);
//int generate_keypair(int length, struct keypair** KP);

// We use "PEM" to make things "readable" for now
int write_key_pem_private(FILE *fp, struct ccn_pkey* private_key_ccn);
int write_key_pem_public(FILE *fp, struct ccn_pkey* private_key_ccn);

PyObject *get_key_pem_private(const struct ccn_pkey *private_key_ccn);
PyObject *get_key_pem_public(const struct ccn_pkey *key_ccn);
PyObject *get_key_der_private(struct ccn_pkey *private_key_ccn);
PyObject *get_key_der_public(struct ccn_pkey *public_key_ccn);
int read_key_pem(FILE *fp, PyObject **py_private_key_ccn,
		PyObject **public_key_ccn, PyObject **py_public_key_digest,
		int *public_key_digest_len);
int put_key_pem(int is_public_only, PyObject *py_key_pem,
		PyObject **py_private_key_ccn, PyObject **py_public_key_ccn,
		PyObject **py_public_key_digest);
int put_key_der(int is_public_only, PyObject *py_key_der,
		PyObject **py_private_key_ccn, PyObject **py_public_key_ccn,
		PyObject **py_public_key_digest, int *public_key_digest_len);
int read_keypair_pem(FILE *fp, struct keypair** KP);
int release_key(struct ccn_pkey** private_key_ccn, struct ccn_pkey** public_key_ccn, unsigned char** public_key_digest);
int release_keypair(struct keypair** KP);

int build_keylocator_from_key(struct ccn_charbuf** keylocator, struct ccn_pkey* key);

int get_ASN_public_key(unsigned char** public_key_der, int* public_key_der_len, struct ccn_pkey* private_key);
RSA *ccn_key_to_rsa(struct ccn_pkey *key_ccn);

#endif /* _KEY_UTILS_H_ */
