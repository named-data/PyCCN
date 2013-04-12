//
//  encryption.h
//  namecrypto
//
//  Originally created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Revised by Wentao Shang <wentao@cs.ucla.edu> to make compatible with NDN.JS
//  Copyright (c) 2013, Regents of the University of California
//  BSD license, See the COPYING file for more information
//

#ifndef __ndn_encryption__
#define __ndn_encryption__

#include <openssl/rsa.h>
#include <openssl/sha.h>

#define KEYLEN 128/8 // symmetric cipher key length in bytes
#define IVLEN 128/8 // IV length in bits
#define MACKLEN 128/8 // mac key length in bits
#define NODE_KEYLEN 128/8 // Long term node key length
#define SESSION_KEYLEN 128/8 // length of a session key
#define SESSIONID_LENGTH IVLEN + SESSION_KEYLEN + MACLEN // length of a session identifier
#define MACLEN SHA256_DIGEST_LENGTH

#define ERR_DECRYPTING_KEM -1
#define ERR_DECRYPTING_DEM -2
#define ERR_ALLOCATION_ERROR -3
#define ERR_DECODING_CIPHERTEXT -4

unsigned char *KDF(const unsigned char *key, unsigned int keylen, const char *s, unsigned int slen);

#endif
