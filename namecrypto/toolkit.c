//
//  toolkit.c
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
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

char * base64_encode(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    char *buff;
    int i;
    
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // All in one line
    
    b64 = BIO_push(b64, bmem);
    if(BIO_write(b64, input, length)<=0)
    {
        BIO_free_all(b64);
        return NULL;   
    }
    
    (void)BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    
    buff = (char *)malloc(bptr->length+1);
    
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    
    BIO_free_all(b64);
    
    //replace '/' with '-'    
    for(i=0; buff[i]; i++)
        if(buff[i] == '/')
            buff[i] = '-';
    
    return buff;
}

unsigned char * base64_decode(char *in)
{
    BIO *b64, *bmem;
    int length = (int)strlen(in);
    int i;
    char * input = (char *)malloc(length+1);
    memcpy(input, in, length + 1);
    
    //replace '-' with '/'  
    for(i=0; input[i]; i++)
        if(input[i] == '-')
            input[i] = '/';
    
    length++;
    
    unsigned char *buffer = (unsigned char *)calloc(1,length);
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // All in one line
    
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    
    if(BIO_read(bmem, buffer, length)<=0)
    {
        free(buffer);
        free(input);
        buffer = NULL;
    }
    
    BIO_free_all(bmem);
    free(input);
    return buffer;
}

unsigned char * base64_decode_len(char *in, int * len)
{
    BIO *b64, *bmem;
    int length = (int)strlen(in);
    int i;
    char * input = (char *)malloc(length+1);
    memcpy(input, in, length + 1);
    
    //replace '-' with '/'  
    for(i=0; input[i]; i++)
        if(input[i] == '-')
            input[i] = '/';
    
    length++;
    
    unsigned char *buffer = (unsigned char *)calloc(1,length);
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // All in one line
    
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    
    if((*len = BIO_read(bmem, buffer, length))<=0)
    {
        free(buffer);
        free(input);
        buffer = NULL;
    }
    
    BIO_free_all(bmem);
    free(input);
    return buffer;
}
