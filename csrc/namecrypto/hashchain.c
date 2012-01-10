//
//  hashchain.c
//  namecrypto
//
//  Created by Naveen Nathan on 12/13/11.
//  Copyright (c) 2011 Naveen Nathan. All rights reserved.
//

#include "hashchain.h"
#include "authentication.h"
#include "encryption.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// for htonl and ntohl
#include <arpa/inet.h>


// creates a new hash chain based on secret and the number of rounds/hashes. Returns an allocation of
// (struct hash_chain) on the heap.
// essentially runs: h^N(h(secret)) where N is num_rounds

int create_hashchain(unsigned char *secret, int secret_len, unsigned int num_rounds, struct hash_chain **hchain)
{
    unsigned int i;
    unsigned char in_buf[SHA256_DIGEST_LENGTH];
    unsigned char out_buf[SHA256_DIGEST_LENGTH];

    // allocate hash chain structure, and assign to pointer passed by caller
    struct hash_chain *h;
    
    if (num_rounds == 0)
        return -1;

    // allocate the hash_chain structure and assign to to caller ptr
    h = malloc(sizeof(*h));
    h->sig = NULL;
    *hchain = h;

    // copy the secret first, this is considered a round
    SHA256(secret, secret_len, in_buf);

    //print_hex(in_buf, SHA256_DIGEST_LENGTH); printf("\n");

    // XXX: add sub-anchors at every 100 iters in the hash_chain structure
    for (i = 0; i < (num_rounds - 1); i++)
    {
        SHA256(in_buf, SHA256_DIGEST_LENGTH, out_buf);

        // copy the digest back into the input digest for the next hash
        memcpy(in_buf, out_buf, SHA256_DIGEST_LENGTH);
    }

    // populate the hash chain
    h->num_rounds = num_rounds;
    memcpy(h->anchor, out_buf, SHA256_DIGEST_LENGTH);
    
    return 0;
}

void free_hashchain(struct hash_chain *h)
{
    if (h && h->sig)
    {
        free(h->sig);
        h->sig = NULL;
    }

    if (h)
        free(h);
}

int verify_hashchain_image(unsigned char *preimage, unsigned char *image, unsigned int num_rounds_offset)
{
    unsigned int i;
    unsigned char in_buf[SHA256_DIGEST_LENGTH];
    unsigned char out_buf[SHA256_DIGEST_LENGTH];
    

    memcpy(in_buf, preimage, SHA256_DIGEST_LENGTH);
    
    for (i = 0; i < num_rounds_offset; i++)
    {
        SHA256(in_buf, SHA256_DIGEST_LENGTH, out_buf);

        // copy the digest back into the input digest for the next hash
        memcpy(in_buf, out_buf, SHA256_DIGEST_LENGTH);
    }

    
    // check the in_buf, incase the num_rounds_offset == 0 (this will be different if out_buf is used for comparison)
    if(!memcmp(image, in_buf, SHA256_DIGEST_LENGTH))
        return AUTH_OK;

    return FAIL_VERIFICATION_FAILED;    
}

int verify_hashchain_challenge(unsigned char *preimage, unsigned char *image)
{
    
    if(!memcmp(image, SHA256(preimage, SHA256_DIGEST_LENGTH, NULL), SHA256_DIGEST_LENGTH))
        return AUTH_OK;

    return FAIL_VERIFICATION_FAILED;    
}


int verify_hashchain_anchor_from_preimage(struct hash_chain *h, unsigned char *preimage, unsigned int preimage_round)
{
    //print_hex(preimage, SHA256_DIGEST_LENGTH); printf("\n");

    return verify_hashchain_image(preimage, h->anchor, h->num_rounds - preimage_round);
}

int verify_hashchain_anchor_from_secret(struct hash_chain *h, unsigned char *secret, unsigned int secret_len)
{
    unsigned char secret_buf[SHA256_DIGEST_LENGTH];

    SHA256(secret, secret_len, secret_buf);

    return verify_hashchain_anchor_from_preimage(h, secret_buf, 0);
}

//int sign_hashchain(struct hash_chain *h, RSA *signing_key)
//{
//    const unsigned int message_len = SHA256_DIGEST_LENGTH + sizeof(h->num_rounds);
//    unsigned char m[message_len];
//    unsigned char md[SHA256_DIGEST_LENGTH];
//    unsigned int sigret;
//
//    // allocate space for rsa sig
//    h->sig = malloc(RSA_size(signing_key));
//
//    memcpy(m, &(h->num_rounds), sizeof(h->num_rounds));
//    memcpy(m + sizeof(h->num_rounds), h->anchor, SHA256_DIGEST_LENGTH);
//
//    SHA256(m, message_len, md);
//
//    RSA_sign(NID_sha256, md, message_len, sigret + 2 + appname_len + statelen, &siglen, signing_key);
//}


// testing functions
void test_hashchain_callback(int a, int b, void *c)
{
    if (a==1)
        fprintf(stderr, ".");
    if (a==2)
        fprintf(stderr, "-");
    if (a==3)
        fprintf(stderr, "+");
}

void test_hashchain()
{
    struct timeval time1, time2;
    unsigned int i;
    const int reps = 1000;
    unsigned int num_rounds = 10000;
    struct hash_chain *h = NULL;

    RSA *rsa_key;
    unsigned char secret[KEYLEN];
    unsigned char secret_hash[SHA256_DIGEST_LENGTH];
    unsigned char in_buf[SHA256_DIGEST_LENGTH];
    unsigned char out_buf[SHA256_DIGEST_LENGTH];
    rsa_key = RSA_generate_key(1024, 65537, test_hashchain_callback, NULL);

    // i-th index selects a preimage of size SHA256_DIGEST_LENGTH
    unsigned char **preimage_table;

    RAND_bytes(secret, KEYLEN);

    // setup SHA hashes to determine the beginning of each chain
    SHA256(secret, KEYLEN, secret_hash);

    //SHA256(secret_hash, SHA256_DIGEST_LENGTH, out_buf);
    //print_hex(out_buf, SHA256_DIGEST_LENGTH); printf("\n");

    memcpy(in_buf, secret_hash, SHA256_DIGEST_LENGTH);
    preimage_table = malloc(num_rounds*sizeof(*preimage_table));
    for (i = 0; i < num_rounds; i++)
    {
        preimage_table[i] = malloc(SHA256_DIGEST_LENGTH);
        SHA256(in_buf, SHA256_DIGEST_LENGTH, preimage_table[i]);
        memcpy(in_buf, preimage_table[i], SHA256_DIGEST_LENGTH);
    }

    //assert(create_hashchain(secret_hash, SHA256_DIGEST_LENGTH, num_rounds, &h) == AUTH_OK);
    //print_hex(preimage_table[num_rounds - 1], SHA256_DIGEST_LENGTH); printf("\n");
    //print_hex(h->anchor, SHA256_DIGEST_LENGTH); printf("\n");
    //assert(!memcmp(preimage_table[num_rounds-1], h->anchor, SHA256_DIGEST_LENGTH));
    //free_hashchain(h);

    printf("\n\n");

    gettimeofday(&time1, NULL);
    for (i=0; i<reps; i++) {
        if(create_hashchain(secret_hash, SHA256_DIGEST_LENGTH, num_rounds, &h) != AUTH_OK)
        {
            printf("FAIL create_hashchain\n");
            exit(1);
        }
        
        //free_hashchain(h);
    }
    gettimeofday(&time2, NULL);
    printf(" create_hashchain  : %.3fusec\n", ((time2.tv_sec - time1.tv_sec)*1000000 + time2.tv_usec - time1.tv_usec)/(reps*1.0));

    // creates hashchain
    assert(create_hashchain(secret_hash, SHA256_DIGEST_LENGTH, num_rounds, &h) == AUTH_OK);

    gettimeofday(&time1, NULL);
    for (i=0; i < num_rounds; i++) {
        //printf("iter %d\n", i);
        //print_hex(preimage_table[i], SHA256_DIGEST_LENGTH); printf("\n");
        if ((verify_hashchain_anchor_from_preimage(h, preimage_table[i], i+1)) != AUTH_OK)
        {
            printf("FAIL verify_hashchain_anchor_from_preimage (incrementing)\n");
            exit(1);
        }
        
    }
    gettimeofday(&time2, NULL);
    printf(" verify_hashchain_anchor_from_preimage (incrementing) : %.3fusec\n", ((time2.tv_sec - time1.tv_sec)*1000000 + time2.tv_usec - time1.tv_usec)/(num_rounds*1.0));



    gettimeofday(&time1, NULL);
    for (i=0; i<reps; i++) {
        if(verify_hashchain_anchor_from_preimage(h, secret_hash, 0) != AUTH_OK)
        {
            printf("FAIL verify_hashchain_anchor_from_preimage\n");
            exit(1);
        }
        
    }
    gettimeofday(&time2, NULL);
    printf(" verify_hashchain_anchor_from_preimage  : %.3fusec\n", ((time2.tv_sec - time1.tv_sec)*1000000 + time2.tv_usec - time1.tv_usec)/(reps*1.0));

    gettimeofday(&time1, NULL);
    for (i=0; i<reps; i++) {
        if(verify_hashchain_anchor_from_secret(h, secret, KEYLEN) != AUTH_OK)
        {
            printf("FAIL verify_hashchain_anchor_from_secret\n");
            exit(1);
        }
        
    }
    gettimeofday(&time2, NULL);
    printf(" verify_hashchain_anchor_from_secret  : %.3fusec\n", ((time2.tv_sec - time1.tv_sec)*1000000 + time2.tv_usec - time1.tv_usec)/(reps*1.0));

    gettimeofday(&time1, NULL);
    for (i=0; i<(2*reps); i+=2) {
        if(verify_hashchain_challenge(preimage_table[i], preimage_table[i+1]) != AUTH_OK)
        {
            printf("FAIL verify_hashchain_challenge\n");
            exit(1);
        }
        
    }
    gettimeofday(&time2, NULL);
    printf(" verify_hashchain_challenge  : %.3fusec\n", ((time2.tv_sec - time1.tv_sec)*1000000 + time2.tv_usec - time1.tv_usec)/(reps*1.0));

    gettimeofday(&time1, NULL);
    for (i=0; i<(reps*50); i++) {
        SHA256(in_buf, SHA256_DIGEST_LENGTH, out_buf);
        memcpy(in_buf, out_buf, SHA256_DIGEST_LENGTH);
    }
    gettimeofday(&time2, NULL);
    printf(" chain_of_50x_SHA256  : %.3fusec\n", ((time2.tv_sec - time1.tv_sec)*1000000 + time2.tv_usec - time1.tv_usec)/(reps*1.0));

    gettimeofday(&time1, NULL);
    for (i=0; i<(reps*100); i++) {
        SHA256(in_buf, SHA256_DIGEST_LENGTH, out_buf);
        memcpy(in_buf, out_buf, SHA256_DIGEST_LENGTH);
    }
    gettimeofday(&time2, NULL);
    printf(" chain_of_100x_SHA256  : %.3fusec\n", ((time2.tv_sec - time1.tv_sec)*1000000 + time2.tv_usec - time1.tv_usec)/(reps*1.0));

    printf("\n");
}
