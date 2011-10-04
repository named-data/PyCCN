//
//  compute_app_secret_key.c
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
//
//  Run by the configuration maneger (CM). The resulting
//  application key must be sent to the application


#include <stdio.h>
#include <string.h>

#include "authentication.h"
#include "toolkit.h"

int main()
{
    unsigned char appname[] = "/ndn/light/switch/room123";
    
    unsigned char appid[APPIDLEN];
    unsigned char app_symm_key[APPKEYLEN];
    unsigned char masterkey[128/8]; // I am using a 128 bit master key, but the size here is not fixed (128 bit is a reasonable size)
    char * policy = "/ndn/light/switch/room123"; // In this example it is a printable '\0'-terminated string but it could be any binary string
    
    FILE * f; int r;
    
    f = fopen("fixture_secret.txt", "r");
    if(!f)
    {
        printf("You have to store a 128 bit secret key in fixture_secret.txt.\nYou can do it using the following command:\n\ndd if=/dev/random of=fixture_secret.txt count=1 bs=16\n\n");
        exit(1);
    }
    
    r = fread(masterkey, 1, 128/8, f);
    fclose(f);
        
    // Compute appid from appname
    appID(appname, strlen((char *)appname)+1, appid); // you can also use "unsigned char * a; a = appID(appname, NULL)"
    
    // Compute the application key from the appid and the policy
    appKey(masterkey, 128/8, appid, (unsigned char *)policy, (int)strlen(policy)+1, app_symm_key);
    
    
    // Store the policy and the application key
    f = fopen("policy.txt", "w");
    fwrite(policy, 1, (int)strlen(policy), f);
    fclose(f);
    
    f = fopen("app_symmetric_key.txt", "w");
    fwrite(app_symm_key, 1, APPKEYLEN, f);
    fclose(f);

    
    printf("Application ID: ");
    print_hex(appid, APPIDLEN);
    printf("\nApplication key: ");
    print_hex(app_symm_key, APPKEYLEN);
    printf("\n");
    
    
    return 0;
}
