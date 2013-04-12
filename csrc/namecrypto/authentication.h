//
//  authentication.h
//  namecrypto
//
//  Originally created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Revised by Wentao Shang <wentao@cs.ucla.edu> to make compatible with NDN.JS
//  Copyright (c) 2013, Regents of the University of California
//  BSD license, See the COPYING file for more information
//
#ifndef __ndn_authentication__
#define __ndn_authentication__
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <ccn/ccn.h>

#define APPIDLEN 128/8
#define APPKEYLEN 128/8

#define AUTH_OK 0
#define FAIL_MISSING_AUTHENTICATOR -1
#define FAIL_VERIFICATION_FAILED -2
#define FAIL_INVALID_POLICY -3
#define FAIL_COMMAND_EXPIRED -4
#define FAIL_INVALID_AUTHENTICATOR -5
#define FAIL_DUPLICATE_INTEREST -6
#define FAIL_VERIFICATION_KEY_NOT_PROVIDED -7
#define FAIL_NO_MEMORY -8

#define INFO_STATE_NOT_VERIFIED -21

#define FORMAT_KEYLOCATOR 1
#define FORMAT_PUBKEY 2

#define PK_AUTH_MAGIC "\x21\x44\x07\x65"
#define SK_AUTH_MAGIC "\x40\x96\x1c\x51"
#define AUTH_MAGIC_LEN 4
#define NOT_AUTHENTICATOR 0
#define AUTH_SYMMETRIC 1
#define AUTH_ASYMMETRIC 2

typedef struct state_st {
    //struct timeval t;
    u_int32_t tv_sec;
    u_int32_t tv_usec;
    u_int32_t seq;
    u_int16_t currRounTripTimeMs;
} state;

void state_init(state * st);
char * retToString(int r);


unsigned char * appID(unsigned char * uniqueAppName, unsigned int uniqueAppName_len, unsigned char * appid);
unsigned char * appKey(unsigned char * k, unsigned int keylen, unsigned char * appID, unsigned char * pol, unsigned int pol_len, unsigned char * appkey);

// Symmetric
void authenticateCommand(state * st, struct ccn_charbuf * commandname, unsigned char * appname, unsigned int appname_len, unsigned char * appkey);

// Public key
void authenticateCommandSig(state * st, struct ccn_charbuf * commandname, unsigned char * appname, unsigned int appname_len, RSA * app_signing_key);

// Use with both symmetric and asymmetric
int verifyCommand(struct ccn_charbuf * authenticatedname, unsigned char * fixtureKey, unsigned int keylen, RSA * pubkey, state * currstate, unsigned long int maxTimeDifferenceMsec, int (*checkPolicy)(unsigned char *, int));

#endif