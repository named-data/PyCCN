//
//  firstauth-cm.c
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
//
//  Run on the fixture. Authenticates an interest
//  received from the configuration maneger (CM) and
//  extracts the deployment information, such as a
//  symmetric (encrypted) and a pubblic key and
//  some additional (encrypted) information.

#include <stdio.h>
#include "encryption.h"
#include "authentication.h"
#include "toolkit.h"

int main()
{
    unsigned char auth_token[4096];
    int len;

    // The initial authenticator is the secret shared by the fixture and the configuration manager (CM). This data is encrypted and authenticated.
    unsigned char *initial_authenticator = (unsigned char *)"123456789012345";

    // The following variables are set by the function verifyFirstEncodedAuthenticator.
    unsigned char *private_info;        // fixture encrypted information (if any)
    unsigned char *additional_info;   // fixture additional (unencrypted) information (if any)
    unsigned int len_private_info;
    unsigned int len_additional_info;

    int rs;
    FILE * f;

    f = fopen("interest.txt", "r");
    if(!f)
    {
        printf("You have to run firstauth-cm first.\n");
        exit(1);
    }

    if(!(len = fread(auth_token, 1, 4096, f)))
    {
        printf("Error reading interest from file\n");
        exit(1);
    }

    rs = verifyFirstAuthenticator(initial_authenticator, 16, auth_token, len, &private_info, &len_private_info, &additional_info, &len_additional_info);

    if (rs == AUTH_OK)
    {
        printf("Interest successfully verified\n");
        printf("The data below is extracted from the interest coming from the configuration manager:\n");
        printf("Encrypted data:   '%s' (len: %d)\n", private_info, len_private_info);
        printf("Unencrypted data: '%s' (len: %d)\n", additional_info, len_additional_info);
    }
    else
        printf("Interest verification failed: %d %s", rs, retToString(rs));

    return 0;
}
