//
//  firstauth-cm.c
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
//
//  Run on the application. Generates an authenticated
//  interest using the application secret key


#include <stdio.h>
#include <string.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include "authentication.h"

int main()
{
    // Application name. Must be a unique name for a specific application
    unsigned char appname[] = "/ndn/light/switch/room123";

    // Fixture name and command name (e.g. switch on light with name "/ndn/uci/room123/light4")
    struct ccn_charbuf * commandname = ccn_charbuf_create();
    ccn_name_from_uri(commandname, "/ndn/uci/room123/light4/switch/on");
    
    // Some key policy (e.g. "This application is allowed to turn off the light only after 5PM on weekdays")
    char policy[2048];
    
    // Application secret key
    unsigned char appkey[APPKEYLEN];
    
    state state_sender;
    unsigned int policylen;
    FILE * f; int r;
    
    // Load the app's secret key
    f = fopen("app_symmetric_key.txt", "r");
    if(!f)
    {
        printf("Application key missing. Please run compute_app_secret first\n");
        exit(1);
    }
    r = fread(appkey, 1, APPKEYLEN, f);
    fclose(f);
    
    // Load the key policy
    f = fopen("policy.txt", "r");
    if(!f)
    {
        printf("Application policy missing. Please run compute_app_secret first\n");
        exit(1);
    }
    policylen = fread(policy, 1, 2048, f);
    fclose(f);
    
    // Initialized the application state. This should be done only once otherwise the state on the 
    // fixture is going to be more recent than the state on the application and the interests will
    // be dropped.
    state_init(&state_sender);
    
    // Construct an authenticated command using the application key
    authenticateCommand(&state_sender, commandname, (unsigned char *)appname, strlen((char *)appname)+1, appkey);
    
    // Store the authenticated command in a file
    f = fopen("interest-symm.txt", "w");
    fwrite(commandname->buf, 1, commandname->length, f);
    fclose(f);
    
    return 0;
}