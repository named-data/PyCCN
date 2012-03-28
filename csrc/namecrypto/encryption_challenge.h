//
//  encryption_challenge.h
//  namecrypto
//
//  Created by Naveen Nathan on 12/15/11.
//  Copyright (c) 2011 Naveen Nathan. All rights reserved.
//

#ifndef __ndn_encryption_challenge__
#define __ndn_encryption_challenge__

#include <openssl/sha.h>

#define CHALLENGELEN 128/8
#define ECHALLENGELEN 128/8
#define HCHALLENGELEN SHA256_DIGEST_LENGTH

int create_encryption_challenge(unsigned char * key, int keylen, unsigned char * e_challenge, unsigned char * h_challenge, unsigned char * challenge);
int answer_challenge(unsigned char * key, int keylen, unsigned char * e_challenge, unsigned char * h_challenge, unsigned char * challenge);
int verify_challenge(unsigned char * key, int keylen, unsigned char * e_challenge, unsigned char * h_challenge, unsigned char * challenge);

#endif
