//
//  toolkit.h
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
//

#ifndef __ndn_toolkit__
#define __ndn_toolkit__


char * base64_encode(const unsigned char *input, int length);
unsigned char *base64_decode(char *input);
unsigned char * base64_decode_len(char *in, int * len);
void print_hex(unsigned char * s, int len);

#endif