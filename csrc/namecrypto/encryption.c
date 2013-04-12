//
//  encryption.c
//  namecrypto
//
//  Originally created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Revised by Wentao Shang <wentao@cs.ucla.edu> to make compatible with NDN.JS
//  Copyright (c) 2013, Regents of the University of California
//  BSD license, See the COPYING file for more information
//

// Limitations: name components (and names) must be shorter than 64KB

#include <string.h>

#include <assert.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "encryption.h"
#include "toolkit.h"

/* Key Derivation Function */
unsigned char *
KDF(const unsigned char *key, unsigned int keylen, const unsigned char *appid, unsigned int appid_len)
{
	unsigned int r;
	unsigned char *ret;

	ret = malloc(MACLEN);
	if (!ret)
		return NULL;

	HMAC(EVP_sha256(), key, keylen, appid, appid_len, ret, &r);

	return ret;
}
