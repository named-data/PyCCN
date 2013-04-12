//
//  toolkit.c
//  namecrypto
//
//  Originally created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Revised by Wentao Shang <wentao@cs.ucla.edu> to make compatible with NDN.JS
//  Copyright (c) 2013, Regents of the University of California
//  BSD license, See the COPYING file for more information
//


#include <stdio.h>

#include "toolkit.h"

void print_hex(unsigned char * s, int len)
{
	for (int i=0 ; i<len ; i++)
	{
		printf("%02X", 0xff & s[i]);
	}
}
