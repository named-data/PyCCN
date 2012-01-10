#ifndef _ndn_hashchain
#define _ndn_hashchain

#include <stdint.h>
#include <openssl/sha.h>

struct hash_chain
{
    uint32_t num_rounds;
    unsigned char anchor[SHA256_DIGEST_LENGTH];
    unsigned char *sig;
};


int create_hashchain(unsigned char *secret, int secret_len, unsigned int num_rounds, struct hash_chain **hchain);

int verify_hashchain_challenge(unsigned char *preimage, unsigned char *image);

int verify_hashchain_image(unsigned char *preimage, unsigned char *image, unsigned int num_rounds_offset);

int verify_hashchain_anchor(struct hash_chain *h, unsigned char *preimage, unsigned int preimage_round);

int verify_hashchain_anchor_from_secret(struct hash_chain *h, unsigned char *secret, unsigned int secret_len);

void free_hashchain(struct hash_chain *h);

void test_hashchain();

#endif
