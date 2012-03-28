//
//  encryption_challenge.c
//  namecrypto
//
//  Created by Naveen Nathan on 12/15/11.
//  Copyright (c) 2011 Naveen Nathan. All rights reserved.
//

#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "encryption_challenge.h"
#include "encryption.h"
#include "authentication.h"
#include "toolkit.h"

// assume that challenge, e_challenge and h_challenges are preallocated buffers of size CHALLENGELEN, ECHALLENGELEN and HCHALLENGELEN respectively
int create_encryption_challenge(unsigned char * key, int keylen, unsigned char * e_challenge, unsigned char * h_challenge, unsigned char * challenge)
{
    AES_KEY aeskey;
    
    if(!RAND_bytes(challenge, CHALLENGELEN))
        return -199;
    
    SHA256(challenge, CHALLENGELEN, h_challenge);
    
    if(AES_set_encrypt_key(key, keylen * 8, &aeskey))
        return -99;
    
    AES_encrypt(challenge, e_challenge, &aeskey);
    
    
//    printf("\n");
//    print_hex(challenge, CHALLENGELEN);
//    printf("  (challenge - create)\n");
//    print_hex(h_challenge, HCHALLENGELEN);    
//    printf("  (h_challenge - create)\n");
    
    return 0;
}

// assume that challenge is a preallocated buffer of size CHALLENGELEN
int answer_challenge(unsigned char * key, int keylen, unsigned char * e_challenge, unsigned char * h_challenge, unsigned char * challenge)
{
    AES_KEY aeskey;
    unsigned char t_challenge[CHALLENGELEN];
    unsigned char t_h_challenge[HCHALLENGELEN];
    
    if(AES_set_decrypt_key(key, keylen * 8, &aeskey))
        return -99;
    
    AES_decrypt(e_challenge, t_challenge, &aeskey);
    
    //now check the challenge and fail if something is wrong
    
    SHA256(t_challenge, CHALLENGELEN, t_h_challenge);
    
    
//    print_hex(t_challenge, CHALLENGELEN);
//    printf("  (challenge - answer)\n");
//    print_hex(t_h_challenge, HCHALLENGELEN);
//    printf("  (t_h_challenge - answer)\n");
//    print_hex(h_challenge, HCHALLENGELEN);    
//    printf("  (h_challenge - answer)\n");

    if(memcmp(t_h_challenge, h_challenge, HCHALLENGELEN))
        return FAIL_VERIFICATION_FAILED; //FAIL
    
    memcpy(challenge, t_challenge, CHALLENGELEN);
    
    return 0;

}


int verify_challenge(unsigned char * key, int keylen, unsigned char * e_challenge, unsigned char * h_challenge, unsigned char * challenge)
{
    AES_KEY aeskey;
    unsigned char t_challenge[CHALLENGELEN];
    unsigned char t_h_challenge[HCHALLENGELEN];
    if(AES_set_decrypt_key(key, keylen * 8, &aeskey))
        return -99;
    
    AES_decrypt(e_challenge, t_challenge, &aeskey);
    
    if(memcmp(t_challenge, challenge, CHALLENGELEN))
        return FAIL_VERIFICATION_FAILED; //FAIL

    SHA256(t_challenge, CHALLENGELEN, t_h_challenge);
    
    if(memcmp(t_h_challenge, h_challenge, HCHALLENGELEN))
        return FAIL_VERIFICATION_FAILED; //FAIL

    return AUTH_OK;
}
