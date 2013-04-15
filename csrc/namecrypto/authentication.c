//
//  authentication.c
//  namecrypto
//
//  Originally created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Revised by Wentao Shang <wentao@cs.ucla.edu> to make compatible with NDN.JS
//  Copyright (c) 2013, Regents of the University of California
//  BSD license, See the COPYING file for more information
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

#include <arpa/inet.h>

#include <ccn/ccn.h>

#include "toolkit.h"
#include "authentication.h"
#include "encryption.h"

//#define AUTHDEBUG

static int verify_update_state_freshness(state * currstate, state * new_state, unsigned long int maxTimeDifferenceMsec);
static int verifyCommandSymm(unsigned char * authenticator, unsigned int auth_len, unsigned char * command_name, unsigned int command_len, unsigned char * fixtureKey, unsigned int key_len, state * currstate, unsigned long int maxTimeDifferenceMsec);
static int verifyCommandSig(unsigned char * authenticator, unsigned int auth_len, unsigned char * command_name, unsigned int command_len, state * currstate, RSA * pubKey, unsigned long maxTimeDifferenceMsec);

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

	case FAIL_NO_MEMORY:
		return("malloc() failed");

	default:
		return("Unknown value\n");
	}

}

/*
 * Given an app_code, generate the SHA256 hash as the app_id (= hash(app_code)).
 * The result is stored in appid if appid!=NULL, otherwise
 * a new buffer is allocated and returned. if appid!=NULL,
 * appid must point to a buffer of size at least APPIDLEN.
 */
unsigned char *
appID(unsigned char *uniqueAppName, unsigned int uniqueAppName_len, unsigned char *appid)
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
 * Given a fixture key k, an application ID appid,
 * appKey creates a secret key for the application and stores it
 * in appkey. appkey must be a memory area of size at least APPKEYLEN
 * or NULL. If NULL, a new memory area of size APPKEYLEN is allocated
 * and returned.
 */

unsigned char *
appKey(unsigned char *k, unsigned int keylen, unsigned char *appid, unsigned char *appkey)
{
	unsigned char *kdf;
	if (!(kdf = KDF(k, keylen, appid, APPIDLEN)))
		return NULL;

#ifdef AUTHDEBUG
	printf("\nFunction appKey\nk     = ");
	print_hex(k, keylen);
	printf("\nappid = ");
	print_hex(appid, APPIDLEN);
	printf("\npol   = ");
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

/*
 * Initializes a preallocated state variable
 */
void
state_init(state * st)
{
	if (st) {
        st->tv_sec = 0;
        st->tv_usec = 0;
		st->seq = 0;
		st->rsvd = 0;
	}
}

/*
 * Updates the current state to reflect the new state
 * after a new authenticator is generated
 */
static void
update_state(state * st)
{
	if (st) {
		struct timeval tmp;
		gettimeofday(&tmp, NULL);
		st->tv_sec = tmp.tv_sec;
		st->tv_usec = tmp.tv_usec;
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
		diff = (int) ((t_now.tv_sec - new_state->tv_sec)*1000000 + t_now.tv_usec - new_state->tv_usec) / 1000;
		if (labs(diff) > maxDelay)
			return FAIL_COMMAND_EXPIRED;
	}

	// The state of the interest looks good. Update current application state
	currstate->seq = new_state->seq;
	currstate->tv_sec = t_now.tv_sec; // should I set the app state to now or to the time in the accepted interest?
	currstate->tv_usec = t_now.tv_usec;

	return AUTH_OK;
}

/*
 * commandname is an NDN name of a light including the command
 * e.g. commandname = /ndn/ucla.edu/apps/TV1/room123/light4/switch/on
 * commandname is ccn_charbuf containing a ccnb encoded name with closing 0x00
 * authenticatedCommand = commandname/(AUTH_MAGIC|appname_len|appname|state|MAC(commandname|appname|state))
 * where appname_len is fixed 2 bytes and AUTH_MAGIC is fixed 4 bytes
 */
void
authenticateCommand(state *st, struct ccn_charbuf *commandname, unsigned char *appname, unsigned int appname_len, unsigned char *appkey)
{
	unsigned char mac[MACLEN];
	unsigned char *m;
	unsigned char *authenticator;
	unsigned char *authenticatorwithmagic;
	int authenticatorlen;
	long int command_len;

	int state_len = sizeof(state);

	int appname_offset = 2;
	int state_offset = appname_offset + appname_len;
	int mac_offset = state_offset + state_len;

	// update and store the current time in "state"
	update_state(st);
    state net_st;  // Convert 'st' into network byte order
    net_st.tv_sec = htonl(st->tv_sec);
    net_st.tv_usec = htonl(st->tv_usec);
    net_st.seq = htonl(st->seq);
    net_st.rsvd = htonl(st->rsvd);

	command_len = commandname->length;

	m = (unsigned char *) malloc(command_len + appname_len + state_len);

	memcpy(m, commandname->buf, command_len);
    memcpy(m + command_len, appname, appname_len);
	memcpy(m + command_len + appname_len, &net_st, state_len);
	HMAC(EVP_sha256(), appkey, APPKEYLEN, m, command_len + appname_len + state_len, mac, NULL);

	authenticatorlen = 2 + appname_len + state_len + MACLEN;
	authenticatorwithmagic = (unsigned char *) malloc(authenticatorlen + AUTH_MAGIC_LEN);
	
    // Add AUTH_MAGIC
    memcpy(authenticatorwithmagic, SK_AUTH_MAGIC, AUTH_MAGIC_LEN);

    // Add appname_len
	authenticator = authenticatorwithmagic + AUTH_MAGIC_LEN;

	authenticator[0] = (appname_len >> 8) & 0xff;
	authenticator[1] = appname_len & 0xff;

    // Add appname
	memcpy(authenticator + appname_offset, appname, appname_len);
	
    // Add state
    //memcpy(authenticator + state_offset, st, state_len);
    memcpy(authenticator + state_offset, &net_st, state_len);
	
    // Add MAC signature
    memcpy(authenticator + mac_offset, mac, MACLEN);

    // Construct authenticated name
	ccn_name_append(commandname, authenticatorwithmagic, authenticatorlen + AUTH_MAGIC_LEN);


#ifdef AUTHDEBUG
	printf("\nFunction authenticateCommand:\nappname= ");
	print_hex(appname, appname_len);
	printf("\nappkey = ");
	print_hex(appkey, APPKEYLEN);
	printf("\nmac    = ");
	print_hex(mac, MACLEN);
	printf("\nm      = ");
	print_hex(m, command_len + appname_len + state_len);
	printf("\n");
#endif

	free(m);
	free(authenticatorwithmagic);
}


/* return NOT_AUTHENTICATOR if no authenticator, AUTH_SYMMETRIC if symmetric, AUTH_ASYMMETRIC if asymmetric */
static int
detect_autenticator(unsigned char * component)
{
	if (!memcmp(component, PK_AUTH_MAGIC, AUTH_MAGIC_LEN))
		return AUTH_ASYMMETRIC;
	if (!memcmp(component, SK_AUTH_MAGIC, AUTH_MAGIC_LEN))
		return AUTH_SYMMETRIC;
    
	return NOT_AUTHENTICATOR;
}

static int
extractFromInterest(unsigned char ** authenticatorwithmagic, unsigned int * auth_len, unsigned char ** prefix, unsigned int * prefix_len, struct ccn_charbuf *name)
{
	struct ccn_indexbuf *nix = ccn_indexbuf_create();
	int num_components, i, atype;
	size_t len;
    
	unsigned char * out;
    
	num_components = ccn_name_split(name, nix);
    
	i = num_components - 1;
	while (i > 0) // The first component cannot be an authenticator
	{
		if (ccn_name_comp_get(name->buf, nix, i, (const unsigned char **) &out, &len)) {
            ccn_indexbuf_destroy(&nix);
			return FAIL_MISSING_AUTHENTICATOR;
        }
		atype = detect_autenticator(out);
		if (atype != NOT_AUTHENTICATOR) {
			*authenticatorwithmagic = (unsigned char *) malloc(len);
			memcpy(*authenticatorwithmagic, out, len);
			*auth_len = (unsigned int) len;
            
			ccn_name_comp_get(name->buf, nix, i - 1, (const unsigned char **) &out, &len);
			*prefix_len = (unsigned int) (len + (out - name->buf)) + 2;
            
#ifdef AUTHDEBUG
            printf("\nextractFromInterest: len=%lu\n", len);
            printf("extractFromInterest: out=%p\n", out);
            printf("extractFromInterest: name->buf=%p\n", name->buf);
            printf("extractFromInterest: prefix_len=%u\n", *prefix_len);
#endif
            
			*prefix = (unsigned char *) malloc(*prefix_len);
			memcpy(*prefix, name->buf, *prefix_len - 1);
            (*prefix)[*prefix_len - 1] = 0x00;  // Put a tailing '0' byte to close the name encoding
            
#ifdef AUTHDEBUG
            printf("extractFromInterest: *prefix=\n");
            print_hex(*prefix, *prefix_len);
            printf("\n");
#endif
            
			ccn_indexbuf_destroy(&nix);
            
			return atype;
		}
		i--;
	}
    
	ccn_indexbuf_destroy(&nix);
    return FAIL_MISSING_AUTHENTICATOR; // No authenticator in the string
}


/* Determines if an interest is authenticated with symmetric or asymmetric crypto and verifies it accordingly */
int
verifyCommand(struct ccn_charbuf *authenticatedname, unsigned char *fixtureKey,
		unsigned int keylen, RSA *pubkey, state *currstate, unsigned long int maxTimeDifferenceMsec)
{
	unsigned char * authenticatorwithmagic, * prefix;
	unsigned int auth_len, prefix_len;
	int ret;

	ret = extractFromInterest(&authenticatorwithmagic, &auth_len, &prefix, &prefix_len, authenticatedname);

	if (FAIL_MISSING_AUTHENTICATOR == ret)
		return FAIL_MISSING_AUTHENTICATOR; // If the authenticator is not present

	switch (ret) {
	case AUTH_ASYMMETRIC:
		if (!pubkey)
			return FAIL_VERIFICATION_KEY_NOT_PROVIDED;

		ret = verifyCommandSig(authenticatorwithmagic + AUTH_MAGIC_LEN,
				auth_len - AUTH_MAGIC_LEN, prefix, prefix_len, currstate, pubkey,
				maxTimeDifferenceMsec);

		break;

	case AUTH_SYMMETRIC:
		if (!(fixtureKey && keylen))
			return FAIL_VERIFICATION_KEY_NOT_PROVIDED;

		ret = verifyCommandSymm(authenticatorwithmagic + AUTH_MAGIC_LEN,
				auth_len - AUTH_MAGIC_LEN, prefix, prefix_len, fixtureKey,
				keylen, currstate, maxTimeDifferenceMsec);

		break;

	default:
		ret = FAIL_MISSING_AUTHENTICATOR;
	}
    
	free(prefix);
    free(authenticatorwithmagic);
    
    return ret;
}

/*
 * maxTimeDifference is the number of seconds that the command can differ from now.
 * Full name = commandname/(AUTH_MAGIC|authenticator)
 * authenticator = appname_len|appname|state|MAC(commandname|appname|state), where appname_len is fixed 2 bytes
 */
int
verifyCommandSymm(unsigned char *authenticator, unsigned int auth_len,
        unsigned char *command_name, unsigned int command_len,
		unsigned char *fixtureKey, unsigned int key_len, state *currstate,
		unsigned long int maxTimeDifferenceMsec)
{
	state * st;
    state host_st;

	int state_len = sizeof(state);
	int appname_len;
	int appname_offset = 2;
	int state_offset;
	int mac_offset;
	int state_ret;
    int msg_len;

	unsigned char * appname;
	unsigned char app_key[APPKEYLEN];
	unsigned char * app_id;
	unsigned char * m;
	unsigned char * mac;
	unsigned char computed_mac[MACLEN];

	appname_len = (authenticator[0] << 8) + authenticator[1];
	state_offset = appname_offset + appname_len;
	mac_offset = state_offset + state_len;
    
    assert (auth_len == (unsigned int)(mac_offset + MACLEN));

	appname = authenticator + appname_offset;
	app_id = appID(appname, appname_len, NULL);
	st = (state *) (authenticator + state_offset);
    host_st.tv_sec = ntohl(st->tv_sec);
    host_st.tv_usec = ntohl(st->tv_usec);
    host_st.seq = ntohl(st->seq);
    host_st.rsvd = ntohl(st->rsvd);
	mac = authenticator + mac_offset;

	// Verify fresnhess of command
	state_ret = verify_update_state_freshness(currstate, &host_st, maxTimeDifferenceMsec);
	if ((state_ret != AUTH_OK) && (state_ret != INFO_STATE_NOT_VERIFIED))
		return state_ret;
    
	// Compute appkey
	appKey(fixtureKey, key_len, app_id, app_key);

    msg_len = command_len + appname_len + state_len;
	m = (unsigned char *) malloc(msg_len);
	memcpy(m, command_name, command_len);
    memcpy(m + command_len, appname, appname_len);
	memcpy(m + command_len + appname_len, authenticator + state_offset, state_len);
    
	HMAC(EVP_sha256(), app_key, APPKEYLEN, m, msg_len, computed_mac, NULL);

#ifdef AUTHDEBUG
	printf("\nFunction verifyCommandSymm:\nappname= ");
	print_hex(appname, appname_len);
	printf("\nappid  = ");
	print_hex(app_id, APPIDLEN);
	printf("\nappkey = ");
	print_hex(app_key, APPKEYLEN);
	printf("\nmac    = ");
	print_hex(mac, MACLEN);
	printf("\ncmac   = ");
	print_hex(computed_mac, MACLEN);
	printf("\nm      = ");
	print_hex(m, command_len + appname_len + state_len);
//	printf("\ncommand_len=%d, state_len=%d, struct timeval t=%lu, time_t=%lu, suseconds_t=%lu, currstate->t.tv_sec=%d\n", command_len, state_len, sizeof(struct timeval), sizeof(time_t), sizeof(suseconds_t), currstate->tv_sec);
    printf("\n");
#endif

	free(m);
	free(app_id);
	if (memcmp(computed_mac, mac, MACLEN))
		return FAIL_VERIFICATION_FAILED;
	else
		return AUTH_OK;
}

/*
 * The authenticated name is constructed as commandname/(AUTH_MAGIC|appname_len|appname|state|RSA_signature)
 * and RSA_signature is Sig(commandname|appname|state) ; commandname doesn't have trailing '/'
 */
void
authenticateCommandSig(state * st, struct ccn_charbuf * commandname, unsigned char * appname, unsigned int appname_len, RSA * app_signing_key)
{
	int command_len;
    int msg_len;
	unsigned int auth_len;
	unsigned char * authenticatorwithmagic;
	unsigned char * authenticator;
	unsigned char * msg;
	unsigned char md[SHA256_DIGEST_LENGTH];

	int state_len = sizeof(state);

	update_state(st);
    state net_st;  // Convert 'st' into network byte order
    net_st.tv_sec = htonl(st->tv_sec);
    net_st.tv_usec = htonl(st->tv_usec);
    net_st.seq = htonl(st->seq);
    net_st.rsvd = htonl(st->rsvd);

	command_len = (int) commandname->length;

	// the signature is computed on <commandname|appname|state> ; commandname doesn't have trailing '/'
    msg_len = command_len + appname_len + state_len;
	msg = (unsigned char *) malloc(msg_len);
	memcpy(msg, commandname->buf, command_len);
	memcpy(msg + command_len, appname, appname_len);
	memcpy(msg + command_len + appname_len, &net_st, state_len);
    
    SHA256(msg, command_len + appname_len + state_len, md);

	authenticatorwithmagic = (unsigned char *) malloc(RSA_size(app_signing_key) + appname_len + state_len + AUTH_MAGIC_LEN + 2);
	memcpy(authenticatorwithmagic, PK_AUTH_MAGIC, AUTH_MAGIC_LEN);
	authenticator = authenticatorwithmagic + AUTH_MAGIC_LEN;
	authenticator[0] = (appname_len >> 8) & 0xff;
	authenticator[1] = appname_len & 0xff;
	memcpy(authenticator + 2, appname, appname_len);
	memcpy(authenticator + 2 + appname_len, &net_st, state_len);
    
    RSA_sign(NID_sha256, md, SHA256_DIGEST_LENGTH, authenticator + 2 + appname_len + state_len, &auth_len, app_signing_key);

#ifdef AUTHDEBUG
	printf("\nFunction authenticateCommandSig:\nappname       = ");
	print_hex(appname, appname_len);
	printf("\nauthenticator = ");
	print_hex(authenticator, 2 + appname_len + state_len);
    printf("\nmsg           = ");
    print_hex(msg, msg_len);
	printf("\nmd            = ");
	print_hex(md, SHA256_DIGEST_LENGTH);
    //printf("\nauth_len      = %u\n", auth_len);
    printf("\n");
#endif

	ccn_name_append(commandname, authenticatorwithmagic, AUTH_MAGIC_LEN + 2 + appname_len + state_len + auth_len);

	free(authenticatorwithmagic);
	free(msg);
}

int
verifyCommandSig(unsigned char * authenticator, unsigned int auth_len, unsigned char * command_name, unsigned int command_len, state * currstate, RSA * pubKey, unsigned long maxTimeDifferenceMsec)
{
	int state_len = sizeof(state);
    int state_ret, appname_len;
	state * st;
    state host_st;
    
	unsigned char * appname;
	unsigned char * signature;
	unsigned char * msg;
	unsigned char * state_s;
	unsigned char md[SHA256_DIGEST_LENGTH];

	appname_len = authenticator[0] * 256 + authenticator[1];
	appname = authenticator + 2;
	state_s = appname + appname_len;
	signature = state_s + state_len;

    assert (auth_len == (unsigned int)(2 + appname_len + state_len + RSA_size(pubKey)));

	// Verify fresnhess of command
	st = (state *) (state_s);
    host_st.tv_sec = ntohl(st->tv_sec);
    host_st.tv_usec = ntohl(st->tv_usec);
    host_st.seq = ntohl(st->seq);
    host_st.rsvd = ntohl(st->rsvd);
	state_ret = verify_update_state_freshness(currstate, &host_st, maxTimeDifferenceMsec);
	if ((state_ret != AUTH_OK) && (state_ret != INFO_STATE_NOT_VERIFIED))
		return state_ret;
	
	// Verify RSA signature
	msg = (unsigned char *) malloc(command_len + appname_len + state_len);
	memcpy(msg, command_name, command_len);
	memcpy(msg + command_len, appname, appname_len);
	memcpy(msg + command_len + appname_len, state_s, state_len);


	SHA256(msg, command_len + appname_len + state_len, md);

#ifdef AUTHDEBUG
	printf("\nFunction verifyCommandSig:\nappname       = ");
	print_hex(appname, appname_len);
	printf("\nauthenticator = ");
	print_hex(authenticator, auth_len - RSA_size(pubKey));
    printf("\nmsg           = ");
    print_hex(msg, command_len + appname_len + state_len);
	printf("\nmd            = ");
	print_hex(md, SHA256_DIGEST_LENGTH);
	printf("\n");
#endif
    
	state_ret = RSA_verify(NID_sha256, md, SHA256_DIGEST_LENGTH, signature, RSA_size(pubKey), pubKey);

	free(msg);

	if (state_ret)
		return AUTH_OK;
	else
		return FAIL_VERIFICATION_FAILED;
}
