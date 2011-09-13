/*
 * Copyright (c) 2011, Regents of the University of California
 * All rights reserved.
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Regents of the University of California nor
 *       the names of its contributors may be used to endorse or promote
 *       products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL REGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

int get_key_pem_public(char** buf, int* length, struct ccn_pkey* private_key_ccn);
PyObject *get_key_der_private(struct ccn_pkey *private_key_ccn);
PyObject *get_key_der_public(struct ccn_pkey *public_key_ccn);
int read_key_pem(FILE *fp, PyObject **py_private_key_ccn,
		PyObject **public_key_ccn, PyObject **py_public_key_digest,
		int *public_key_digest_len);
int put_key_der(int is_public_only, PyObject *py_key_der,
		PyObject **py_private_key_ccn, PyObject **py_public_key_ccn,
		PyObject **py_public_key_digest, int *public_key_digest_len);
int read_keypair_pem(FILE *fp, struct keypair** KP);
int release_key(struct ccn_pkey** private_key_ccn, struct ccn_pkey** public_key_ccn, unsigned char** public_key_digest);
int release_keypair(struct keypair** KP);

int build_keylocator_from_key(struct ccn_charbuf** keylocator, struct ccn_pkey* key);

int get_ASN_public_key(unsigned char** public_key_der, int* public_key_der_len, struct ccn_pkey* private_key);

#endif /* _KEY_UTILS_H_ */
