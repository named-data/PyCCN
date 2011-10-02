//
//  firstauth-cm.c
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
//
//  Run by the configuration maneger (CM). The resulting
//  interest is sent to the fixture to perform the first
//  initialization

#include <stdio.h>
#include "encryption.h"
#include "authentication.h"
#include "toolkit.h"



int main()
{
    unsigned char * authenticator_token;
    int len;
    
    // The initial authenticator is the secret shared by the fixture and the configuration manager (CM). This data is encrypted and authenticated.
    unsigned char * initial_authenticator = (unsigned char *)"123456789012345"; // len = 16 (with \0)
    
    // The fixture secret key is a symmetri key sent by the CM to the fixture during the initial authentication through an interest
    unsigned char * private_info            = (unsigned char *)"s-key  from  CM"; // len = 16
    
    // additional_info contains some additional data that the CM wants to send to the fixture. This data is encrypted and authenticated.
    unsigned char * additional_info       = (unsigned char *)"some additional info";  // len = 21
    
    FILE * f;
    
    // Stores the interest name in the buffer returned by the function.
    len = buildFirstAuthenticator(initial_authenticator, 16, private_info, 16, additional_info, 21, &authenticator_token);
    
    f = fopen("interest.txt", "w");
    fwrite(authenticator_token, 1, len, f);
    fclose(f);
    
    printf("The data below has been stored and authenticated in an interest: \n");
    printf("Encrypted info:   '%s'\n", private_info);
    printf("Unencrypted info: '%s'\n", additional_info);

    return 0;
}
