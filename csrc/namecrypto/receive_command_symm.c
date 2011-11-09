//
//  firstauth-cm.c
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
//
//  Run on the fixture. Authenticates an interest
//  received from an application.


#include <stdio.h>
#include <string.h>

#include "authentication.h"


int cb_yes(unsigned char * appname, int appname_length)
{
    return 1;
}

int cb_no(unsigned char * appname, int appname_length)
{
    return 0;
}

int main()
{
    int r;
    struct ccn_charbuf * authenticatedCommand;
    unsigned char masterkey[128/8];
    state state_fixture;
    FILE * f;
    
    // not pretty, but gets the job done at least for an example (this is not going to be necessary in a real application)
    authenticatedCommand = (struct ccn_charbuf *)malloc(sizeof(struct ccn_charbuf));
    authenticatedCommand->buf = (unsigned char *)malloc(4096);
    authenticatedCommand->limit = 4096;
    
    // Read the fixture (master) secret key from file
    f = fopen("fixture_secret.txt", "r");
    if(!f)
    {
        printf("Application secret key missing.\n");
        exit(1);
    }
    r = fread(masterkey, 1, 128/8, f);
    fclose(f);
    
    // Read the interest from file
    f = fopen("interest-symm.txt", "r");
    if(!f)
    {
        printf("Interest missing.\n");
        exit(1);
    }
    r = fread(authenticatedCommand->buf, 1, 4096, f);
    authenticatedCommand->length = r;
    fclose(f);
    
    // Initialize the state of the fixture. Must be done only once per application
    state_init(&state_fixture);
    
    // Verify the command against the current state
    r = verifyCommand(authenticatedCommand, masterkey, 128/8, NULL /*RSA key*/, &state_fixture, 3600000, cb_yes);
    
    printf("%s", retToString(r));
    return 0;
}
