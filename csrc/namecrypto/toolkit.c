//
//  toolkit.c
//  namecrypto
//
//  Originally created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Revised by Wentao Shang <wentao@cs.ucla.edu> to make compatible with NDN.JS
//  Copyright (c) 2013, Regents of the University of California
//  BSD license, See the COPYING file for more information
//


#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "toolkit.h"

void print_hex(unsigned char * s, int len)
{
	int i;
	for (i=0 ; i<len ; i++)
	{
		printf("%02X", 0xff & s[i]);
	}
}
