

#ifndef KEY_UTILS_H_
#define KEY_UTILS_H_

// Load these here to make it easier on the app

// On MacOS X, need to have the latest version from MacPorts
// and add /opt/local/include as an include path
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ossl_typ.h>



#include <ccn/keystore.h>

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

int generate_key(int length, struct ccn_pkey** private_key_ccn, struct ccn_pkey** public_key_ccn,
					unsigned char** public_key_digest, size_t *public_key_digest_len);
int generate_keypair(int length, struct keypair** KP);

// We use "PEM" to make things "readable" for now
int write_key_pem(FILE *fp, struct ccn_pkey* private_key_ccn);
int write_key_pem_public(FILE *fp, struct ccn_pkey* private_key_ccn);

int get_key_pem_public(char** buf, int* length, struct ccn_pkey* private_key_ccn);
int read_key_pem(FILE *fp, struct ccn_pkey** private_key_ccn, struct ccn_pkey** public_key_ccn,
		unsigned char** public_key_digest, size_t *public_key_digest_len);
int read_keypair_pem(FILE *fp, struct keypair** KP);
int release_key(struct ccn_pkey** private_key_ccn, struct ccn_pkey** public_key_ccn, unsigned char** public_key_digest);
int release_keypair(struct keypair** KP);

int build_keylocator_from_key(struct ccn_charbuf** keylocator, struct ccn_pkey* key);

int get_ASN_public_key(unsigned char** public_key_der, int* public_key_der_len, struct ccn_pkey* private_key);


// internal

int create_public_key_digest(RSA* private_key_rsa, unsigned char** public_key_digest, size_t *public_key_digest_len);
int ccn_keypair_from_rsa(RSA* private_key_rsa, struct ccn_pkey** private_key_ccn, struct ccn_pkey** public_key_ccn);
int generate_RSA_keypair(unsigned char** private_key_der, size_t *private_key_len,
						 unsigned char** public_key_der, size_t *public_key_len);



#endif /* KEY_UTILS_H_ */
