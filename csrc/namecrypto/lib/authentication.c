//
//  authentication.c
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
//

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <ccn/ccn.h>

#include "toolkit.h"
#include "authentication.h"
#include "encryption.h"

//#define AUTHDEBUG

int verify_update_state_freshness(state * currstate, state * new_state, unsigned long int maxTimeDifferenceMsec);
int parseAuthenticator_token(unsigned char * authenticator_token, unsigned int authenticator_token_len, unsigned char ** encrypted_info, unsigned int * encrypted_info_len, unsigned char ** unencrypted_info, unsigned int * unencrypted_info_len, unsigned char ** mac)
;
int verifyCommandSymm(unsigned char * authenticator, unsigned int auth_len, unsigned char * authenticatedCommand, unsigned int commandLen, unsigned char * fixtureKey, unsigned int keylen, state * currstate, unsigned long int maxTimeDifferenceMsec, int (*checkPolicy)(unsigned char *, int));
int verifyCommandSig(unsigned char * authenticator, unsigned int authenticator_len, unsigned char * command, unsigned int command_len, state * currstate, RSA * pubKey, unsigned long maxTimeDifferenceMsec);

char *
retToString(int r)
{
	switch (r) {
	case AUTH_OK:
		return("Interest verification successful\n");

	case FAIL_MISSING_AUTHENTICATOR:
		return("Missing or corrupted interest authenticator\n");

	case FAIL_VERIFICATION_FAILED:
		return("Incorrect interest authenticator\n");

	case FAIL_INVALID_POLICY:
		return("Invalid interest policy\n");

	case FAIL_COMMAND_EXPIRED:
		return("Interest expired\n");

	case FAIL_DUPLICATE_INTEREST:
		return("Duplicate interest\n");

	case FAIL_VERIFICATION_KEY_NOT_PROVIDED:
		return("The appropriate verification key has not been supplied\n");

	default:
		return("Unknown value\n");
	}

}

/*
 * The result is stored in appid if appid!=NULL, otherwise
 * a new buffer is allocated and returned. if appid!=NULL,
 * appid must point to a buffer of size at least APPIDLEN.
 */
unsigned char *
appID(unsigned char * uniqueAppName, unsigned int uniqueAppName_len, unsigned char * appid)
{
	unsigned char * s;

	assert(SHA256_DIGEST_LENGTH >= APPIDLEN);

	if (!(s = (unsigned char *) malloc(SHA256_DIGEST_LENGTH)))
		return NULL;

	SHA256((unsigned char *) uniqueAppName, uniqueAppName_len, s);

	if (!appid) {
		//appid == NULL
		unsigned char * tmp;
		if (!(tmp = (unsigned char *) malloc(APPIDLEN)))
			return NULL;
		memcpy(tmp, s, APPIDLEN);
		free(s);
		return tmp;
	} else {
		//appid != NULL
		memcpy(appid, s, APPIDLEN);
		free(s);
		return appid;
	}
}

/*
 * Given a fixture key k, an application ID app and a policy pol,
 * appKey creates a secret key for the application and stores it
 * in appkey. appkey must be a memory area of size at least APPKEYLEN
 * or NULL. If NULL, a new memory area of size APPKEYLEN is allocated
 * and returned.
 */

unsigned char *
appKey(unsigned char * k, unsigned int keylen, unsigned char * appid, unsigned char * pol, unsigned int pol_len, unsigned char * appkey)
{
	unsigned char * kdf;
	char * s = (char *) malloc(APPIDLEN + pol_len);

	if (!s)
		return NULL;

	memcpy(s, appid, APPIDLEN);
	memcpy(s + APPIDLEN, pol, pol_len);

	if (!(kdf = KDF(k, keylen, s, APPIDLEN + pol_len)))
		return NULL;

	free(s);

#ifdef AUTHDEBUG
	printf("\nFunction appKey\nk     = ");
	print_hex(k, keylen);
	printf("\nappid = ");
	print_hex(appid, APPIDLEN);
	printf("\npol   = ");
	print_hex(pol, pol_len);
	printf("\nkdf   = ");
	print_hex(kdf, APPIDLEN);
	printf("\n");
#endif


	if (appkey) {
		// appkey != NULL
		memcpy(appkey, kdf, APPKEYLEN);
		free(kdf);
		return appkey;
	}

	return kdf;
}

//return NOT_AUTHENTICATOR if no authenticator, AUTH_SYMMETRIC if symmetric, AUTH_ASYMMETRIC if asymmetric

int
detect_autenticator(unsigned char * component)
{
	if (!memcmp(component, PK_AUTH_MAGIC, AUTH_MAGIC_LEN))
		return AUTH_ASYMMETRIC;
	if (!memcmp(component, SK_AUTH_MAGIC, AUTH_MAGIC_LEN))
		return AUTH_SYMMETRIC;

	return NOT_AUTHENTICATOR;
}

int
extractFromInterest(unsigned char ** authenticator, unsigned int * auth_len, unsigned char ** data, unsigned int * data_len, struct ccn_charbuf *name)
{
	struct ccn_indexbuf *nix = ccn_indexbuf_create();
	int num_components, i, atype;
	size_t len;

	unsigned char * out;

	num_components = ccn_name_split(name, nix);

	i = num_components - 1;
	while (i > 0) // The first component cannot be an authenticator
	{
		if (ccn_name_comp_get(name->buf, nix, i, (const unsigned char **) &out, &len))
			return FAIL_MISSING_AUTHENTICATOR;
		atype = detect_autenticator(out);
		if (atype != NOT_AUTHENTICATOR) {
			*authenticator = (unsigned char *) malloc(len);
			memcpy(*authenticator, out, len);
			*auth_len = (unsigned int) len;

			ccn_name_comp_get(name->buf, nix, i - 1, (const unsigned char **) &out, &len);
			*data_len = (unsigned int) (len + (out - name->buf));

			*data = (unsigned char *) malloc(*data_len);
			memcpy(*data, name->buf, *data_len);

			ccn_indexbuf_destroy(&nix);

			return atype;
		}
		i--;
	}

	return FAIL_MISSING_AUTHENTICATOR; // No authenticator in the string
}

/*
 * Initializes a preallocated state variable
 */
void
state_init(state * st)
{
	if (st) {
		st->seq = 0;
		st->currRounTripTimeMs = 0;
	}
}

/*
 * Updates the current state to reflect the new state
 * after a new authenticator is generated
 */
void
update_state(state * st)
{
	if (st) {
		gettimeofday(&(st->t), NULL);
		st->seq++;
	}
}

int
verify_update_state_freshness(state * currstate, state * new_state, unsigned long int maxDelay)
{
	long int diff;
	struct timeval t_now;

	if (!currstate || !new_state)
		return INFO_STATE_NOT_VERIFIED;

	// Check if the interest has a sequence number greater than the last sequence number
	if ((currstate->seq) >= (new_state->seq))
		return FAIL_DUPLICATE_INTEREST;

	//Check if the interest is recent
	gettimeofday(&t_now, NULL);
	if (maxDelay > 0) {
		diff = (int) ((t_now.tv_sec - (new_state->t).tv_sec)*1000000 + t_now.tv_usec - (new_state->t).tv_usec) / 1000;
		if (labs(diff) > maxDelay)
			return FAIL_COMMAND_EXPIRED;
	}

	// The state of the interest looks good. Update current application state
	currstate->seq = new_state->seq;
	(currstate->t).tv_sec = t_now.tv_sec; // should I set the app state to now or to the time in the accepted interest?
	(currstate->t).tv_usec = t_now.tv_usec;

	return AUTH_OK;
}

/*
 * commandname is a full NDN name of a light including the command
 * e.g. commandname = /ndn/uci/room123/light4/switch/on
 * commandname is a '\0' terminated C string.
 * authenticatedCommand = commandname/Base64(appname_len||appname||state||MAC(commandname||state))
 */

//COMMANDNAME IS A CCN_BUFFER, LIKE APPNAME ETC.
//WHEN DUMP CCN_BUFFER TO STRING, ASSERT(SIZEOF(CCN_BUFFER) == SIZEOF(INT) * 2 + SIZEOF(CHAR *))
//struct ccn_charbuf *tempContentObj = ccn_charbuf_create();

void
authenticateCommand(state *st, struct ccn_charbuf *commandname,
		unsigned char *appname, unsigned int appname_len, unsigned char *appkey)
{
	unsigned char mac[MACLEN];
	unsigned char *m;
	unsigned char *authenticator;
	unsigned char *authenticatorwithmagic;
	int authenticatorlen;
	long int commandnameLen;

	int statelen = sizeof(state);

	int appname_offset = 2;
	int state_offset = appname_offset + appname_len;
	int mac_offset = state_offset + statelen;

	// update and store the current time in "state"
	update_state(st);

	// skip the initial 0xf2 and final 0x00
	commandnameLen = commandname->length - 2;

	m = (unsigned char *) malloc(commandnameLen + statelen);

	memcpy(m, commandname->buf + 1, commandnameLen);
	memcpy(m + commandnameLen, st, statelen);
	HMAC(EVP_sha256(), appkey, APPKEYLEN, m, commandnameLen + statelen, mac, NULL);

	authenticatorlen = 2 + appname_len + statelen + MACLEN;
	authenticatorwithmagic = (unsigned char *) malloc(authenticatorlen + AUTH_MAGIC_LEN);
	memcpy(authenticatorwithmagic, SK_AUTH_MAGIC, AUTH_MAGIC_LEN);

	authenticator = authenticatorwithmagic + AUTH_MAGIC_LEN;

	authenticator[0] = (appname_len >> 8) & 0xFF;
	authenticator[1] = appname_len & 0xFF;

	memcpy(authenticator + appname_offset, appname, appname_len);
	memcpy(authenticator + state_offset, st, statelen);
	memcpy(authenticator + mac_offset, mac, MACLEN);

	ccn_name_append(commandname, authenticatorwithmagic, authenticatorlen + AUTH_MAGIC_LEN);
	//    ccn_charbuf_append(authenticatedname, authenticator, authenticatorlen);


#ifdef AUTHDEBUG
	printf("\nFunction authenticateCommand:\nappname= ");
	print_hex(appname, appname_len);
	printf("\nappkey = ");
	print_hex(appkey, APPKEYLEN);
	printf("\nmac    = ");
	print_hex(mac, MACLEN);
	printf("\nm      = ");
	print_hex(m, commandnameLen + statelen);
	printf("\n");
#endif

	free(m);
	free(authenticatorwithmagic);
}

/* Determines if an interest is authenticated with symmetric or asymmetric crypto and verifies it accordingly */
int
verifyCommand(struct ccn_charbuf * authenticatedname, unsigned char * fixtureKey, unsigned int keylen, RSA * pubkey, state * currstate, unsigned long int maxTimeDifferenceMsec, int (*checkPolicy)(unsigned char *, int))
{
	unsigned char * authenticator, * data;
	unsigned int auth_len, data_len;
	int ret;

	ret = extractFromInterest(&authenticator, &auth_len, &data, &data_len, authenticatedname);

	if (FAIL_MISSING_AUTHENTICATOR == ret)
		return FAIL_MISSING_AUTHENTICATOR; // If the authenticator is not present

	switch (ret) {
	case AUTH_ASYMMETRIC:
		if (!pubkey)
			return FAIL_VERIFICATION_KEY_NOT_PROVIDED;
		ret = verifyCommandSig(authenticator + AUTH_MAGIC_LEN, auth_len - AUTH_MAGIC_LEN, data, data_len, currstate, pubkey, maxTimeDifferenceMsec);
		free(data);
		free(authenticator);
		return ret;
		break;

	case AUTH_SYMMETRIC:
		if (!(fixtureKey && keylen))
			return FAIL_VERIFICATION_KEY_NOT_PROVIDED;
		ret = verifyCommandSymm(authenticator + AUTH_MAGIC_LEN, auth_len - AUTH_MAGIC_LEN, data + 1, data_len, fixtureKey, keylen, currstate, maxTimeDifferenceMsec, checkPolicy);
		free(data);
		free(authenticator);
		return ret;
		break;

	default:
		return FAIL_MISSING_AUTHENTICATOR;
	}
	return 0; // Just to avoid complaints from the compiler -- never gets here.
}

/*
 * maxTimeDifference is the number of seconds that the command can differ from now.
 * authenticatedCommand = commandname/Base64(appname_len||appname||state||MAC(commandname||state))
 */
int
verifyCommandSymm(unsigned char * authenticator, unsigned int auth_len, unsigned char * authenticatedCommand, unsigned int commandLen, unsigned char * fixtureKey, unsigned int keylen, state * currstate, unsigned long int maxTimeDifferenceMsec, int (*checkPolicy)(unsigned char *, int))
{
	state * st;

	int statelen = sizeof(state);
	int appname_len;
	int appname_offset = 2;
	int state_offset;
	int mac_offset;
	int stateRet;

	unsigned char * appname;
	unsigned char appkey[APPKEYLEN];
	unsigned char * appid;
	unsigned char * m;
	unsigned char * mac;
	unsigned char computedmac[MACLEN];

	appname_len = authenticator[0] * 256 + authenticator[1];
	state_offset = appname_offset + appname_len;
	mac_offset = state_offset + statelen;

	appname = authenticator + appname_offset;
	appid = appID(appname, appname_len, NULL);
	st = (state *) (authenticator + state_offset);
	mac = authenticator + mac_offset;

	// Verify fresnhess of command

	stateRet = verify_update_state_freshness(currstate, st, maxTimeDifferenceMsec);
	if ((stateRet != AUTH_OK) && (stateRet != INFO_STATE_NOT_VERIFIED))
		return stateRet;


	// Verify poloicy related to appname through callback function (if present)
	if (checkPolicy) {
		if (!checkPolicy(appname, appname_len))
			return FAIL_INVALID_POLICY;
	}

	// Compute appkey
	appKey(fixtureKey, keylen, appid, appname, appname_len, appkey);

	m = (unsigned char *) malloc(commandLen + statelen);
	memcpy(m, authenticatedCommand, commandLen);
	memcpy(m + commandLen, authenticator + state_offset, statelen);

	HMAC(EVP_sha256(), appkey, APPKEYLEN, m, commandLen + statelen, computedmac, NULL);

#ifdef AUTHDEBUG
	printf("\nFunction verifyCommandSymm:\nappname= ");
	print_hex(appname, appname_len);
	printf("\nappid  = ");
	print_hex(appid, APPIDLEN);
	printf("\nappkey = ");
	print_hex(appkey, APPKEYLEN);
	printf("\nmac    = ");
	print_hex(mac, MACLEN);
	printf("\ncmac   = ");
	print_hex(computedmac, MACLEN);
	printf("\nm      = ");
	print_hex(m, commandLen + statelen);
#endif

	free(m);
	//free(authenticatorwithmagic);
	free(appid);
	if (memcmp(computedmac, mac, MACLEN))
		return FAIL_VERIFICATION_FAILED;
	else
		return AUTH_OK;
}

/*
 * The interest is constructed as /command/Base64(appnamelen|Appname|state|RSA_signature)
 * and RSA_signature is Sig(commandname|appid|state) ; commandname doesn't have
 * trailing '/'
 */
//void authenticateCommandSig(char ** authenticatedCommand, state * st, char * commandName, unsigned char * appID, RSA * app_signing_key)

void
authenticateCommandSig(state * st, struct ccn_charbuf * commandname, unsigned char * appname, unsigned int appname_len, RSA * app_signing_key)
{
	int namelen;
	unsigned int siglen;
	unsigned char * sigretwithmagic;
	unsigned char * sigret;
	unsigned char * m;
	unsigned char md[SHA256_DIGEST_LENGTH];

	int statelen = sizeof(state);

	update_state(st);

	namelen = (int) commandname->length - 2;

	// the signature is computed on <commandname||appname||state> ; commandname doesn't have trailing '/'

	m = (unsigned char *) malloc(namelen + appname_len + statelen);
	memcpy(m, commandname->buf, namelen);
	memcpy(m + namelen, appname, appname_len);
	memcpy(m + namelen + appname_len, st, statelen);

	sigretwithmagic = (unsigned char *) malloc(RSA_size(app_signing_key) + appname_len + statelen + AUTH_MAGIC_LEN + 2);
	memcpy(sigretwithmagic, PK_AUTH_MAGIC, AUTH_MAGIC_LEN);
	sigret = sigretwithmagic + AUTH_MAGIC_LEN;
	sigret[0] = (appname_len >> 8) & 0xFF;
	sigret[1] = appname_len & 0xFF;
	memcpy(sigret + 2, appname, appname_len);
	memcpy(sigret + 2 + appname_len, st, statelen);

	SHA256(m, namelen + appname_len + statelen, md);

	RSA_sign(NID_sha256, md, SHA256_DIGEST_LENGTH, sigret + 2 + appname_len + statelen, &siglen, app_signing_key);

#ifdef AUTHDEBUG
	printf("\nFunction authenticateCommandSig:\nappname   = ");
	print_hex(appname, appname_len);
	printf("\nsigretwithmagic = ");
	print_hex(sigretwithmagic, AUTH_MAGIC_LEN + 2 + siglen + appname_len + statelen);
	printf("\nmd =         ");
	print_hex(md, SHA256_DIGEST_LENGTH);
	printf("\n");
#endif


	ccn_name_append(commandname, sigretwithmagic, AUTH_MAGIC_LEN + 2 + siglen + appname_len + statelen);

	free(sigretwithmagic);
	free(m);
}

int
verifyCommandSig(unsigned char * authenticator, unsigned int authenticator_len, unsigned char * command, unsigned int command_len, state * currstate, RSA * pubKey, unsigned long maxTimeDifferenceMsec)
{
	int statelen = sizeof(state), stateRet, appname_len;
	state * st;
	unsigned char * appname;
	unsigned char * signature;
	unsigned char * signed_msg;
	unsigned char * state_s;
	unsigned char md[SHA256_DIGEST_LENGTH];

	appname_len = authenticator[0] * 256 + authenticator[1];
	appname = authenticator + 2;
	state_s = appname + appname_len;
	signature = state_s + statelen;



	// Verify fresnhess of command
	st = (state *) (state_s);
	stateRet = verify_update_state_freshness(currstate, st, maxTimeDifferenceMsec);
	if ((stateRet != AUTH_OK) && (stateRet != INFO_STATE_NOT_VERIFIED)) {
		//free(authenticator);
		return stateRet;
	}
	// Verify RSA signature
	signed_msg = (unsigned char *) malloc(command_len + appname_len + statelen);
	memcpy(signed_msg, command, command_len);
	memcpy(signed_msg + command_len, appname, appname_len);
	memcpy(signed_msg + command_len + appname_len, st, statelen);


	SHA256(signed_msg, command_len + appname_len + statelen, md);

#ifdef AUTHDEBUG
	printf("\nFunction verifyCommandSig:\nappname   = ");
	print_hex(appname, appname_len);
	printf("\nsigretwithmagic =         ");
	print_hex(authenticator, authenticator_len);
	printf("\nmd =         ");
	print_hex(md, SHA256_DIGEST_LENGTH);
	printf("\n");
#endif
	stateRet = RSA_verify(NID_sha256, md, SHA256_DIGEST_LENGTH, signature, RSA_size(pubKey), pubKey);

	//    free(authenticator);
	free(signed_msg);


	if (stateRet)
		return AUTH_OK;
	else
		return FAIL_VERIFICATION_FAILED;
}

/*
 * First authentication:
 *
 * CM and fixture share an initial authenticator IA
 *
 * encrypted_info_len || encrypted_info || unencrypted_info_len || unencrypted_info || MAC
 *
 * - encrypted_info_len: 2 bytes. Can be 0. In this case, there is no encrypted information
 * - encrypted_info: some private information sent encrypted to the light. encrypted_info is encrypted under key KDF(IA, 1)
 * - unencrypted_info_len: 2 bytes. Can be 0. In this case no unencrypted information is present.
 * - unencrypted_info: some public unencrypted BUT AUTHENTICATED information
 * - MAC: length is MACLEN, is computed on all the previous components using the key KDF(IA,0)
 *
 */
int
buildFirstAuthenticator(unsigned char * initial_authenticator, unsigned int initial_authenticator_len, unsigned char * encrypted_info, unsigned int encrypted_info_len, unsigned char * unencrypted_info, unsigned int unencrypted_info_len, unsigned char ** authenticator_token)
{
	int authenticatorLen = 0;
	unsigned char * mac_key;
	unsigned char * aes_key = NULL;

	unsigned int encrypted_info_offset, unencrypted_info_offset, mac_offset;

	int encrypted_info_enc_len = encrypted_info_len;

	if (encrypted_info_enc_len)
		encrypted_info_enc_len += IVLEN;

	encrypted_info_offset = 2;
	unencrypted_info_offset = encrypted_info_offset + encrypted_info_enc_len + 2;
	mac_offset = unencrypted_info_offset + unencrypted_info_len;

	authenticatorLen = mac_offset + MACLEN;

	mac_key = KDF(initial_authenticator, initial_authenticator_len, "\0", 1);


	*authenticator_token = (unsigned char *) malloc(authenticatorLen);


	// encrypted_info
	(*authenticator_token)[0] = (encrypted_info_enc_len >> 8) & 0xFF;
	(*authenticator_token)[1] = encrypted_info_enc_len & 0xFF;

	if (encrypted_info_enc_len) {
		aes_key = KDF(initial_authenticator, initial_authenticator_len, "\1", 1);
		symm_enc_no_mac(encrypted_info, encrypted_info_len, (*authenticator_token) + encrypted_info_offset, aes_key);
	}

	// unencrypted_info
	(*authenticator_token)[unencrypted_info_offset - 2] = (unencrypted_info_len >> 8) & 0xFF;
	(*authenticator_token)[unencrypted_info_offset - 1] = unencrypted_info_len & 0xFF;

	if (unencrypted_info_len)
		memcpy((*authenticator_token) + unencrypted_info_offset, unencrypted_info, unencrypted_info_len);

	HMAC(EVP_sha256(), mac_key, MACKLEN, (*authenticator_token), mac_offset, (*authenticator_token) + mac_offset, NULL);

	free(mac_key);
	if (aes_key)
		free(aes_key);
	return authenticatorLen;
}

int
parseAuthenticator_token(unsigned char * authenticator_token, unsigned int authenticator_token_len, unsigned char ** encrypted_info, unsigned int * encrypted_info_len, unsigned char ** unencrypted_info, unsigned int * unencrypted_info_len, unsigned char ** mac)
{
	unsigned char * curr;

	int tot_len = 0;

	*encrypted_info_len = authenticator_token[0]*256 + authenticator_token[1];
	tot_len += *encrypted_info_len + 2;
	*encrypted_info = authenticator_token + 2;

	curr = (*encrypted_info) + (*encrypted_info_len);

	*unencrypted_info_len = curr[0]*256 + curr[1];
	tot_len += *unencrypted_info_len + 2;
	*unencrypted_info = curr + 2;

	*mac = (*unencrypted_info) + (*unencrypted_info_len);

	if (tot_len == authenticator_token_len - MACLEN)
		return tot_len;
	else
		return FAIL_INVALID_AUTHENTICATOR;
}

int
verifyFirstAuthenticator(unsigned char * initial_authenticator, unsigned int initial_authenticator_len, unsigned char * authenticator_token, unsigned int authenticator_token_len, unsigned char ** encrypted_info, unsigned int * encrypted_info_len, unsigned char ** unencrypted_info, unsigned int * unencrypted_info_len)
{
	unsigned char * mac_key;
	unsigned char * aes_key = NULL;
	unsigned char mac[MACLEN];
	unsigned char * amac;
	unsigned char * tmp_encrypted_info, * tmp_unencrypted_info;
	int mac_offset;


	mac_offset = parseAuthenticator_token(authenticator_token, authenticator_token_len, &tmp_encrypted_info, encrypted_info_len, &tmp_unencrypted_info, unencrypted_info_len, &amac);
	if (mac_offset < 0)
		return mac_offset;


	// Verify MAC
	mac_key = KDF(initial_authenticator, initial_authenticator_len, "\0", 1);
	HMAC(EVP_sha256(), mac_key, MACKLEN, authenticator_token, mac_offset, mac, NULL);
	if (memcmp(mac, authenticator_token + mac_offset, MACLEN))
		return FAIL_VERIFICATION_FAILED;


	// Copy encrypted and unencrypted information

	if (*encrypted_info_len) {
		aes_key = KDF(initial_authenticator, initial_authenticator_len, "\1", 1);
		*encrypted_info = (unsigned char *) malloc(*encrypted_info_len - IVLEN);
		symm_dec_no_mac(tmp_encrypted_info, *encrypted_info_len, *encrypted_info, aes_key);
		*encrypted_info_len -= IVLEN;
	}


	if (*unencrypted_info_len) {
		*unencrypted_info = (unsigned char *) malloc(*unencrypted_info_len);
		memcpy(*unencrypted_info, tmp_unencrypted_info, *unencrypted_info_len);
	}


	free(mac_key);
	if (aes_key)
		free(aes_key);
	return AUTH_OK;
}

/*
 * Similar to buildFirstAuthenticator, but the auhtenticator here is encoded
 * using "my" Base64. ('-' rather than '/') and attached to a fixture name:
 * e.g. fixture name = /ndn/uci/room123/light1. authenticator =
 * /ndn/uci/room123/light1/Aasdadd[..]==
 * fixture_mame can be NULL. In that case, only the encoded authenticator is
 * returned.
 */
char *
buildEncodedFirstAuthenticatorForFixture(char * fixture_name, unsigned char * initial_authenticator, unsigned int initial_authenticator_len, unsigned char * encrypted_info, unsigned int encrypted_info_len, unsigned char * unencrypted_info, unsigned int unencrypted_info_len)
{
	char * ret;
	char * encoded;
	unsigned char * authenticator_token;
	int authlen;
	int fxname_len, encodedlen;

	authlen = buildFirstAuthenticator(initial_authenticator, initial_authenticator_len, encrypted_info, encrypted_info_len, unencrypted_info, unencrypted_info_len, &authenticator_token);

	encoded = base64_encode(authenticator_token, authlen);

	if (fixture_name) {
		fxname_len = (int) strlen(fixture_name);
		if (fixture_name[fxname_len - 1] == '/')
			fxname_len--; // remove trailing '/' from fixture name
		encodedlen = (int) strlen(encoded);

		ret = (char *) malloc(fxname_len + encodedlen + 2);
		memcpy(ret, fixture_name, fxname_len);
		ret[fxname_len] = '/';
		memcpy(ret + fxname_len + 1, encoded, encodedlen + 1);
		free(encoded);
		free(authenticator_token);
		return ret;
	}

	return encoded;
}

/*
 * encoded_authenticator_token can be both a name with authenticator (e.g. /ndn/uci/room123/light1/Aasdadd[..]==)
 * or just the encoded authenticator (e.g. Aasdadd[..]==)
 */

int
verifyFirstEncodedAuthenticator(unsigned char * initial_authenticator, unsigned int initial_authenticator_len, char * encoded_authenticator_token, unsigned char ** encrypted_info, unsigned int * encrypted_info_len, unsigned char ** unencrypted_info, unsigned int * unencrypted_info_len)
{
	unsigned char * decoded;
	int len;
	int ret;
	char * encoded_auth;

	encoded_auth = strrchr(encoded_authenticator_token, '/');
	if (encoded_auth)
		encoded_authenticator_token = encoded_auth + 1;

	decoded = base64_decode_len(encoded_authenticator_token, &len);
	ret = verifyFirstAuthenticator(initial_authenticator, initial_authenticator_len, decoded, len, encrypted_info, encrypted_info_len, unencrypted_info, unencrypted_info_len);
	free(decoded);
	return ret;
}
