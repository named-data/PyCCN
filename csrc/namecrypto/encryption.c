//
//  encryption.c
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
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

int symmetric_encrypt_binary(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char * key, unsigned char * session_id, unsigned char ** encrypted_name);

int symmetric_decrypt_binary(unsigned char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char * key, unsigned char ** plaintext);

unsigned char *
KDF(const unsigned char *key, unsigned int keylen, const char *s, unsigned int slen) // change this with something like HKDF
{
	unsigned int r;
	unsigned char *ret;

	ret = malloc(MACLEN);
	if (!ret)
		return NULL;

	HMAC(EVP_sha256(), key, keylen, (const unsigned char *) s, slen, ret, &r);

	return ret;
}

int
symm_enc_no_mac(const unsigned char *plaintext, unsigned int plaintext_length,
		unsigned char *ciphertext, const unsigned char *key)
{
	unsigned char ecount_buf[AES_BLOCK_SIZE];
	unsigned int num = 0;
	unsigned char IV[IVLEN];
	AES_KEY aeskey;

	if (!RAND_bytes(IV, IVLEN))
		return -1;

	memset(ecount_buf, 0, AES_BLOCK_SIZE);
	memcpy(ciphertext, IV, IVLEN);

	if (AES_set_encrypt_key(key, KEYLEN * 8, &aeskey))
		return -2;

	AES_ctr128_encrypt(plaintext, ciphertext + IVLEN, plaintext_length, &aeskey, IV, ecount_buf, &num);

	return plaintext_length + IVLEN;
}

// len is the length of ciphertext + IV

int
symm_dec_no_mac(const unsigned char *ciphertext, unsigned int ciphertext_length,
		unsigned char *plaintext, const unsigned char *key)
{
	unsigned char ecount_buf[AES_BLOCK_SIZE];
	unsigned char IV[IVLEN];
	unsigned int num = 0;

	AES_KEY aeskey;

	if (AES_set_encrypt_key(key, KEYLEN * 8, &aeskey))
		return -2;

	memset(ecount_buf, 0, AES_BLOCK_SIZE);
	memcpy(IV, ciphertext, IVLEN);

	AES_ctr128_encrypt(ciphertext + IVLEN, plaintext, ciphertext_length - IVLEN, &aeskey, IV, ecount_buf, &num);

	return 0;
}

int
symm_enc(unsigned char * plaintext, unsigned int plaintext_length, unsigned char * ciphertext, unsigned char * key)
{
	unsigned char ecount_buf[AES_BLOCK_SIZE];
	unsigned char * aes_key;
	unsigned char * mac_key;
	unsigned int num = 0;
	unsigned char IV[IVLEN];
	AES_KEY aeskey;

	aes_key = KDF(key, KEYLEN, "\0", 1);
	mac_key = KDF(key, KEYLEN, "\1", 1);

	if (!RAND_bytes(IV, IVLEN))
		return -1;

	memset(ecount_buf, 0, AES_BLOCK_SIZE);
	memcpy(ciphertext, IV, IVLEN);

	if (AES_set_encrypt_key(aes_key, KEYLEN * 8, &aeskey))
		return -2;

	AES_ctr128_encrypt(plaintext, ciphertext + IVLEN, plaintext_length, &aeskey, IV, ecount_buf, &num);
	HMAC(EVP_sha256(), mac_key, MACKLEN, ciphertext, IVLEN + plaintext_length, ciphertext + plaintext_length + IVLEN, NULL);

	free(aes_key);
	free(mac_key);
	return 0;
}

unsigned char *
encrypt_data(unsigned char * plaintext, unsigned int len, unsigned char * ciphertext, unsigned int * ciphertextlen, unsigned char * key, unsigned int keylen)
{
	int ret;
	*ciphertextlen = len + IVLEN + MACLEN;

	assert(keylen = 16);
	if (!ciphertext)
		ciphertext = (unsigned char *) malloc(*ciphertextlen);

	if ((ret = symm_enc(plaintext, len, ciphertext, key)))
		*ciphertextlen = ret;
	return ciphertext;
}

int
dem_encrypt(unsigned char * plaintext, unsigned int len, unsigned char * dem, unsigned char * sesskey)
{
	if (!RAND_bytes(sesskey, KEYLEN))
		return -1;

	return symm_enc(plaintext, len, dem, sesskey);
}

// len does not consider the mac, but only the message

int
dem_decrypt(unsigned char * dem, unsigned int len, unsigned char * plaintext, unsigned char * sesskey)
{
	unsigned char ecount_buf[AES_BLOCK_SIZE];
	unsigned char IV[IVLEN];
	unsigned char mac[MACLEN];
	unsigned char * aes_key;
	unsigned char * mac_key;
	unsigned int num;

	AES_KEY aeskey;

	//    printf("\nciphertext = ");
	//    print_hex(dem, len + IVLEN + MACLEN);


	aes_key = KDF(sesskey, KEYLEN, "\0", 1);
	mac_key = KDF(sesskey, KEYLEN, "\1", 1);

	if (AES_set_encrypt_key(aes_key, KEYLEN * 8, &aeskey))
		return -2;

	memset(ecount_buf, 0, AES_BLOCK_SIZE);
	num = 0;
	memcpy(IV, dem, IVLEN);

	HMAC(EVP_sha256(), mac_key, MACKLEN, dem, len + IVLEN, mac, NULL);


	//    printf("\naes_key1   = ");
	//    print_hex(aes_key, 16);
	//    printf("\nmac_key1   = ");
	//    print_hex(mac_key, 16);
	//    printf("\nIV1        = ");
	//    print_hex(IV, 16);
	//    printf("\n");


	//    printf("\nMACmsg1  %d= ", len+IVLEN);
	//    print_hex(dem, len+IVLEN);
	//    printf("\nMAC_KEY1   = ");
	//    print_hex(mac_key, 16);
	//    printf("\nMAC1       = ");
	//    print_hex(mac, MACLEN);
	//    printf("\nMAC2       = ");
	//    print_hex(dem+len+IVLEN, MACLEN);
	//    printf("\nmsg1       = ");
	//    print_hex(dem+IVLEN, 16);

	if (memcmp(mac, dem + len + IVLEN, MACLEN))
		return -3;

	AES_ctr128_encrypt(dem + IVLEN, plaintext, len, &aeskey, IV, ecount_buf, &num);

	free(aes_key);
	free(mac_key);
	return 0;

}

//alias for dem_decrypt

int
symm_dec(unsigned char * ciphertext, unsigned int len, unsigned char * plaintext, unsigned char * key)
{
	return dem_decrypt(ciphertext, len, plaintext, key);
}

// if ciphertext

unsigned char *
decrypt_data(unsigned char * ciphertext, unsigned int ciphertext_length, unsigned char * plaintext, unsigned int * len, unsigned char * key, unsigned int keylen)
{
	int ret;
	int plainlen = ciphertext_length - IVLEN - MACLEN;

	assert(keylen = 16);

	if (!plaintext)
		plaintext = (unsigned char *) malloc(plainlen);

	if ((ret = dem_decrypt(ciphertext, plainlen, plaintext, key)))
		*len = ret;
	else
		*len = plainlen;

	return plaintext;
}

int
kem_encrypt(int len, unsigned char * session_key, unsigned char * ciphertext, RSA * key)
{
	return RSA_public_encrypt(len, session_key, ciphertext, key, RSA_PKCS1_OAEP_PADDING);
}

int
kem_decrypt(int len, unsigned char * kem, unsigned char * session_key, RSA * key)
{
	return RSA_private_decrypt(len, kem, session_key, key, RSA_PKCS1_OAEP_PADDING);
}

/*
 * Encrypts a name or a subset of a name using RSA-OAEP.
 */

int
encrypt_name(unsigned char * name, unsigned int name_length, RSA * key, unsigned char ** encrypted_name)
{
	int kemlen;
	int modsize;
	unsigned char * kem;
	unsigned char * dem;
	unsigned char sesskey[KEYLEN];

	modsize = BN_num_bytes(key->n);

	*encrypted_name = (unsigned char *) malloc(2 + modsize + 2 + IVLEN + name_length + MACLEN); // len KEM + KEM + len DEM + DEM (AES-CTR w/ IV + MAC)

	kem = *encrypted_name;
	dem = *encrypted_name + 2 + modsize;

	dem_encrypt(name, name_length, dem + 2, sesskey);

	kemlen = kem_encrypt(KEYLEN, sesskey, kem + 2, key);

	assert(kemlen == modsize); // modsize == kemlen

	kem[0] = (modsize >> 8) & 0xFF;
	kem[1] = modsize & 0xFF;

	dem[0] = (name_length >> 8) & 0xFF;
	dem[1] = name_length & 0xFF;


	return 2 + modsize + 2 + IVLEN + name_length + MACLEN;
}

/*
 * Decrypts a name encrypted using "encrypt" above
 * Returns the length of the encrypted payload, or a negative
 * value in case of error.
 * The length of encrypted_name is implicit in the format
 */
int
decrypt_name(unsigned char * encrypted_name, RSA * key, unsigned char ** plaintext)
{
	int demlen;
	int kemlen;
	unsigned char * kem;
	unsigned char * dem;
	unsigned char sesskey[KEYLEN];

	kemlen = (encrypted_name[0] & 0xFF) * 256 + (encrypted_name[1] & 0xFF);
	kem = encrypted_name;
	dem = encrypted_name + kemlen + 2;
	demlen = (dem[0] & 0xFF) * 256 + (dem[1] & 0xFF);

	*plaintext = (unsigned char *) malloc(demlen);

	if (kem_decrypt(kemlen, kem + 2, sesskey, key) == -1)
		return ERR_DECRYPTING_KEM;

	if (dem_decrypt(dem + 2, demlen, *plaintext, sesskey))
		return ERR_DECRYPTING_DEM;

	return demlen;
}

int
ciphsize(unsigned char * ciphertext)
{
	int kemlen;
	int demlen;

	kemlen = ciphertext[0] * 256 + ciphertext[1];
	demlen = ciphertext[2 + kemlen] * 256 + ciphertext[2 + kemlen + 1] + IVLEN + MACLEN;
	return 2 + kemlen + 2 + demlen;
}

/*
 * Attaches a symmetric key (if present) and encrypts name
 */

int
encrypt_binary(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, RSA * key, unsigned char ** encrypted_name)
{
	unsigned char * toEncrypt; // toEncrypt = name_length || name || symmk_length || symmkey
	int toEncryptLen;
	int name_offset;
	int symmkey_offset;
	int ciphlen;

	if (!symmkey)
		symmkey_length = 0;

	name_offset = 2;
	symmkey_offset = name_offset + name_length + 2;

	// Build the string toEncrypt as name_length || name || symmk_length || symmkey
	toEncryptLen = 2 + name_length + 2 + symmkey_length;
	if (!(toEncrypt = (unsigned char *) malloc(toEncryptLen)))
		return ERR_ALLOCATION_ERROR;
	memcpy(toEncrypt + name_offset, name, name_length);
	if (symmkey)
		memcpy(toEncrypt + symmkey_offset, symmkey, symmkey_length);

	toEncrypt[0] = (name_length >> 8) & 0xFF;
	toEncrypt[1] = name_length & 0xFF;

	toEncrypt[2 + name_length + 0] = (symmkey_length >> 8) & 0xFF;
	toEncrypt[2 + name_length + 1] = symmkey_length & 0xFF;


	// Encrypt toEncrypt
	ciphlen = encrypt_name(toEncrypt, toEncryptLen, key, encrypted_name);

	free(toEncrypt);

	return ciphlen;
}

/*
 * Same as above, but it also
 * encodes the ciphertext in "pseudo-base64" (where '/' is replaced with
 * '-') a name.
 */

int
encrypt_encode(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, RSA * key, unsigned char ** encrypted_name)
{

	int ciphlen;
	unsigned char * ciph;

	ciphlen = encrypt_binary(name, name_length, symmkey, symmkey_length, key, &ciph);

	// Encode in Base64 the ciphertext
	*encrypted_name = (unsigned char *) base64_encode(ciph, ciphlen);

	free(ciph);
	return(int) strlen((char*) *encrypted_name);
}

int
decrypt_binary(unsigned char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, RSA * key, unsigned char ** plaintext)
{
	unsigned char * plain; //  name_length || name || symmk_length || symmkey
	int msglen;
	int name_offset;
	int symmkey_offset;

	// Decrypt decoded ciphertext
	msglen = decrypt_name(encrypted_name, key, &plain);
	if (msglen < 0)
		return msglen;

	// Extract name and symmetric key
	msglen = plain[0] * 256 + plain[1];
	*symmkey_length = plain[2 + msglen + 0] * 256 + plain[2 + msglen + 1];

	name_offset = 2;
	symmkey_offset = name_offset + msglen + 2;

	*plaintext = (unsigned char *) malloc(msglen);
	*symmkey = (unsigned char *) malloc(*symmkey_length);

	memcpy(*plaintext, plain + name_offset, msglen);
	memcpy(*symmkey, plain + symmkey_offset, *symmkey_length);

	return msglen;
}

/*
 * Decodes and decrypt the output of the previous function.
 * Encrypted_name is a NULL-terminated C string.
 */

int
decrypt_decode(char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, RSA * key, unsigned char ** plaintext)
{
	unsigned char * ciph; // E(name_length || name || symmk_length || symmkey)
	int msglen;

	// Decode base64 ciphertext
	if (!(ciph = base64_decode(encrypted_name)))
		return ERR_DECODING_CIPHERTEXT;

	msglen = decrypt_binary(ciph, symmkey, symmkey_length, key, plaintext);
	free(ciph);

	return msglen;
}

/*
 * Same as above but with sessions
 * Output: encrypted name = Base64(session_id || len of tEl ||  E(name_length || name || symmk_length || symmkey))
 * where tEl = name_length || name || symmk_length || symmkey
 */
int
symmetric_encrypt_encode(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char * key, unsigned char * session_id, unsigned char ** encrypted_name)
{
	unsigned char * ciph;
	int ciphlen;
	ciphlen = symmetric_encrypt_binary(name, name_length, symmkey, symmkey_length, key, session_id, &ciph);

	// Encode in Base64 the ciphertext
	*encrypted_name = (unsigned char *) base64_encode(ciph, ciphlen);

	free(ciph);
	return(int) strlen((char*) *encrypted_name);
}

/* Same as above without base64 */
int
symmetric_encrypt_binary(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char * key, unsigned char * session_id, unsigned char ** encrypted_name)
{
	unsigned char * toEncrypt; // toEncrypt = name_length || name || symmk_length || symmkey
	int toEncryptLen;
	int name_offset;
	int symmkey_offset;
	int ciphlen;

	if (!symmkey)
		symmkey_length = 0;

	name_offset = 2;
	symmkey_offset = name_offset + name_length + 2;
	toEncryptLen = 2 + name_length + 2 + symmkey_length;

	// Build the string toEncrypt as name_length || name || symmk_length || symmkey
	if (!(toEncrypt = (unsigned char *) malloc(toEncryptLen)))
		return ERR_ALLOCATION_ERROR;
	memcpy(toEncrypt + name_offset, name, name_length);
	if (symmkey)
		memcpy(toEncrypt + symmkey_offset, symmkey, symmkey_length);

	toEncrypt[0] = (name_length >> 8) & 0xFF;
	toEncrypt[1] = name_length & 0xFF;

	toEncrypt[2 + name_length + 0] = (symmkey_length >> 8) & 0xFF;
	toEncrypt[2 + name_length + 1] = symmkey_length & 0xFF;


	/*
	 * Now we have the message to encrypt in toEncrypt. It's time to prepare the
	 * buffer for the ciphertext
	 */
	ciphlen = SESSIONID_LENGTH + 2 + toEncryptLen + IVLEN + MACLEN;
	*encrypted_name = (unsigned char *) malloc(ciphlen);

	//put the sessionid at the beginning of ciph
	memcpy(*encrypted_name, session_id, SESSIONID_LENGTH);

	// Encrypt toEncrypt and put the ciphertext after the sessionid
	if (symm_enc(toEncrypt, toEncryptLen, (*encrypted_name) + 2 + SESSIONID_LENGTH, key))
		return -1;

	(*encrypted_name)[SESSIONID_LENGTH] = (toEncryptLen >> 8) & 0xFF;
	(*encrypted_name)[SESSIONID_LENGTH + 1] = toEncryptLen & 0xFF;


	//ciphlen = encrypt_name(toEncrypt, toEncryptLen, key, &ciph);


	//    printf("\nEncrypt %d %d: ciph = ", ciphlen, ciphsize(ciph));
	//    print_hex(ciph, ciphsize(ciph)); //ciphlen);
	//    printf("\n");

	free(toEncrypt);
	return ciphlen;
}

/*
 * Decodes and decrypt the output of the previous function.
 * Encrypted_name is a NULL-terminated C string.
 */

int
symmetric_decrypt_decode(unsigned char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char * key, unsigned char ** plaintext)
{
	unsigned char * ciph;
	int len;
	// Decode base64 ciphertext
	if (!(ciph = base64_decode((char *) encrypted_name)))
		return ERR_DECODING_CIPHERTEXT;
	len = symmetric_decrypt_binary(ciph, symmkey, symmkey_length, key, plaintext);

	free(ciph);
	return len;
}

/* Same as above without base64 */
int
symmetric_decrypt_binary(unsigned char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char * key, unsigned char ** plaintext)
{
	unsigned char * plain; //  name_length || name || symmk_length || symmkey
	unsigned char * sessionkey;
	int r;
	int msglen;
	int ciphlen;
	int name_offset;
	int symmkey_offset;


	// Extract the session key from the session_id
	if (SESSION_KEYLEN != getSessionKey(encrypted_name, &sessionkey, key))
		return -1;


	// Decrypt decoded ciphertext
	ciphlen = encrypted_name[SESSIONID_LENGTH] * 256 + encrypted_name[SESSIONID_LENGTH + 1];
	plain = (unsigned char *) malloc(ciphlen);
	r = dem_decrypt(encrypted_name + SESSIONID_LENGTH, ciphlen, plain, sessionkey);

	if (r < 0)
		return r;

	// Extract name and symmetric key
	msglen = plain[0] * 256 + plain[1];
	*symmkey_length = plain[2 + msglen + 0] * 256 + plain[2 + msglen + 1];

	name_offset = 2;
	symmkey_offset = name_offset + msglen + 2;

	*plaintext = (unsigned char *) malloc(msglen);
	*symmkey = (unsigned char *) malloc(*symmkey_length);

	memcpy(*plaintext, plain + name_offset, msglen);
	memcpy(*symmkey, plain + symmkey_offset, *symmkey_length);

	return msglen;
}

/*
 * Encrypts a name for an anonymizing node.
 * symmkey can be NULL, in which case
 * symmkey_length is ignored.
 * encryptedName is a Base64-encoded string
 * symmkey is the key chosen by the client
 * under which the signature and the original
 * name of the content is encrypted.
 * Public key encryption is used. For symmetric
 * encryption-only, use session_encrypt_for_node
 */
int
encrypt_name_for_node_B64(RSA * node_pubkey, unsigned char * privateName, int privateName_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName)
{
	return encrypt_encode((unsigned char *) privateName, privateName_length, symmkey, symmkey_length, node_pubkey, encryptedName);
}

/* Same as above without base64 */
int
encrypt_name_for_node(RSA * node_pubkey, unsigned char * privateName, int privateName_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName)
{
	return encrypt_binary(privateName, privateName_length, symmkey, symmkey_length, node_pubkey, encryptedName);
}

/*
 * Run on an anonymizing node. Decrypts a name
 * and possibly symmetric key in input
 * Input is E(name||k) (e.g. E([interest]||k))
 */

int
decrypt_name_on_node_B64(char * ciphertext, RSA * node_pubkey, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char ** decryptedName)
{
	return decrypt_decode(ciphertext, symmkey, symmkey_length, node_pubkey, decryptedName);
}

/* Same as above without base64 */
int
decrypt_name_on_node(unsigned char * ciphertext, RSA * node_pubkey, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char ** decryptedName)
{
	return decrypt_binary(ciphertext, symmkey, symmkey_length, node_pubkey, decryptedName);
}

/*
 * Run on an encrypting node. The client requests
 * a new session and receives session_id and key.
 * node_key is provided by the node environment
 * The encryption of the key into the session id
 * is probabilistic. It could be deterministic,
 * but because of the birthday paradox the long
 * term key would be useful for less than O(sqrt(k))
 * sessions. (is it true here as well? think...)
 */

int
createSession(unsigned char ** session_id, unsigned char ** key, unsigned char * node_key)
{
	int ret;

	*key = (unsigned char *) malloc(SESSION_KEYLEN);
	*session_id = (unsigned char *) malloc(SESSIONID_LENGTH);

	if (!RAND_bytes(*key, KEYLEN))
		return -1;

	if ((ret = symm_enc(*key, SESSION_KEYLEN, *session_id, node_key)))
		return ret;

	return SESSIONID_LENGTH;
}

/*
 * Run on an ecnrypting node. The client sends
 * the session ID and the node retrieves the
 * corresponding session key
 */
int
getSessionKey(unsigned char * session_id, unsigned char ** key, unsigned char * node_key)
{
	*key = (unsigned char *) malloc(SESSION_KEYLEN);
	return dem_decrypt(session_id, SESSION_KEYLEN, *key, node_key);
}

/*
 * Encrypts a name for an anonymizing node. nodeName is a NULL-terminated string.
 * symmkey can be NULL, in which case symmkey_length is ignored.
 * encryptedName is a NULL-terminated string that contains nodeName||/||E(privateName)
 * symmkey is the key chosen by the client under which the signature and the original name
 * of the content is encrypted.
 */
int
session_encrypt_name_for_node_B64(unsigned char * sessionkey, unsigned char * session_id, unsigned char * privateName, int privateName_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName)
{
	return symmetric_encrypt_encode(privateName, privateName_length, symmkey, symmkey_length, sessionkey, session_id, encryptedName);
}

/* Same as above without base64 */
int
session_encrypt_name_for_node(unsigned char * sessionkey, unsigned char * session_id, unsigned char * privateName, int privateName_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName)
{
	return symmetric_encrypt_binary(privateName, privateName_length, symmkey, symmkey_length, sessionkey, session_id, encryptedName);
}

/*
 * Run on an anonymizing node. Decrypts a name and possibly symmetric key in input
 * Input is /nodename/E(name||k) (e.g. /ndn/uci/anonymizer/E(/ndn/ucla/secret||k))
 * encrypted by session_encrypt_for_node.
 */

int
session_decrypt_name_on_node_B64(unsigned char * ciphertext, int ciphertext_length, unsigned char * node_key, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char ** decryptedName)
{
	return symmetric_decrypt_decode(ciphertext, symmkey, symmkey_length, node_key, decryptedName);
}

/* Same as above without base64 */
int
session_decrypt_name_on_node(unsigned char * ciphertext, int ciphertext_length, unsigned char * node_key, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char ** decryptedName)
{
	return symmetric_decrypt_binary(ciphertext, symmkey, symmkey_length, node_key, decryptedName);
}
