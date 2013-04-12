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

#define MACLEN SHA256_DIGEST_LENGTH

unsigned char *KDF(const unsigned char *key, unsigned int keylen, const unsigned char *appid, unsigned int appid_len);

#endif
