//
//  encoding.c
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
//

#include "encoding.h"


/*
 * Encoding: t|a|l|d
 * t = type: 'e' for encryption, 's' for signature
 * a = algorithm: if t='e', a=0x01 => RSA-OAEP
 * l = length in bytes of the encoding data d
 * d = BASE64 encoding of data. If t='e', d = l1|kem|l2|dem
 * 
 */

