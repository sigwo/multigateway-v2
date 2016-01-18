// created by chanc3r
// MIT License

#ifndef nxt17codec_h
#define nxt17codec_h

#include <string.h>
#include <stdlib.h>

//  --------------------------------------------------------------------------
//  Reference implementation for rfc.zeromq.org/spec:32/Z85
//
//  This implementation provides a Z85 codec as an easy-to-reuse C class
//  designed to be easy to port into other languages.

//  --------------------------------------------------------------------------
//  Copyright (c) 2010-2013 iMatix Corporation and Contributors
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
//  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
//  --------------------------------------------------------------------------
//  (c) 2015 chanc3r - modified to work with fixed length buffers and return
//  length of encoded bytes - 0 is returned still if encoding fails.

#include <stdint.h>
#include <stdio.h>
#include <assert.h>

//  Basic language taken from CZMQ's prelude
typedef unsigned char byte;
#define streq(s1,s2) (!strcmp ((s1), (s2)))

//  Maps base 256 to base 85
static char encoder [85 + 1] = {
    "0123456789"
    "abcdefghij"
    "klmnopqrst"
    "uvwxyzABCD"
    "EFGHIJKLMN"
    "OPQRSTUVWX"
    "YZ.-:+=^!/"
    "*?&<>()[]{"
    "}@%$#"
};

//  Maps base 85 to base 256
//  We chop off lower 32 and higher 128 ranges
static byte decoder [96] = {
    0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00,
    0x4B, 0x4C, 0x46, 0x41, 0x00, 0x3F, 0x3E, 0x45,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x40, 0x00, 0x49, 0x42, 0x4A, 0x47,
    0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
    0x3B, 0x3C, 0x3D, 0x4D, 0x00, 0x4E, 0x43, 0x00,
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x4F, 0x00, 0x50, 0x00, 0x00
};

//  --------------------------------------------------------------------------
//  Encode a byte array as a string and return the number of bytes encoded.

size_t
Z85_encode (byte *raw_data, size_t raw_size, byte* encoded, size_t enc_size)
{
    //  Accepts only byte arrays bounded to 4 bytes
    if (raw_size % 4) return 0;
    
    size_t encoded_size = raw_size * 5 / 4;
    uint char_nbr = 0;
    uint byte_nbr = 0;
    uint32_t value = 0;
    
    if(encoded_size > enc_size) return 0;
    while (byte_nbr < raw_size) {
        //  Accumulate value in base 256 (binary)
        value = value * 256 + raw_data [byte_nbr++];
        if (byte_nbr % 4 == 0) {
            //  Output value in base 85
            uint divisor = 85 * 85 * 85 * 85;
            while (divisor) {
                encoded [char_nbr++] = encoder [value / divisor % 85];
                divisor /= 85;
            }
            value = 0;
        }
    }
    assert (char_nbr == encoded_size);
    encoded [char_nbr] = 0;
    return encoded_size;
}


//  --------------------------------------------------------------------------
//  Decode an encoded string into a byte array; size of array will be
//  strlen (string) * 4 / 5.

size_t
Z85_decode (char *string, unsigned char *bytes, size_t byte_size)
{
    //  Accepts only strings bounded to 5 bytes
    if (strlen (string) % 5)
        return 0;
    
    size_t decoded_size = strlen (string) * 4 / 5;
    if(decoded_size>byte_size) return 0;
    
    size_t byte_nbr = 0;
    size_t char_nbr = 0;
    uint32_t value = 0;
    while (char_nbr < strlen (string)) {
        //  Accumulate value in base 85
        value = value * 85 + decoder [(byte) string [char_nbr++] - 32];
        if (char_nbr % 5 == 0) {
            //  Output value in base 256
            uint divisor = 256 * 256 * 256;
            while (divisor) {
                bytes [byte_nbr++] = value / divisor % 256;
                divisor /= 256;
            }
            value = 0;
        }
    }
    assert (byte_nbr == decoded_size);
    return byte_nbr;
}

int hexstr2bytes(const char *hex, byte* bytes, size_t byte_size) {
    int byte_count=0;
    size_t len=strlen(hex);
    if(len%2) return 0; // has to be an even number of bytes
    for (int i=0; i<len; i+=2, byte_count++) {
	int value;
        if(sscanf(&hex[i],"%2x",&value) <= 0) return 0;
	bytes[byte_count]=value;
    }
    return byte_count;

}

int bytes2hexstr(const byte* bytes, size_t byte_count, char *hex, size_t hex_size) {
    int hex_count=0;
    if(hex_size<2*byte_count) return 0; // hex array is 2 x size of byte array
    for(int i=0; i<byte_count; i++, hex_count+=2)
        sprintf(&hex[hex_count],"%02x",bytes[i]);
    return hex_count;
}

#include "cJSON.h"

//Encoding structure

//Bytes 00,01 - bit mask of the fields the array contains - bit set - field is present
//Bytes 03 - version character - set to 01 - will only change if we need to update the encding that breaks backward compatibility.
//Bytes 04-160 - encoded data
//  strings are copied
//  number is represented as 2,4,8 or 16 digit hex number (signed so 16bit is +/- 32767 in input/output
//  float is represented as 8 digit hex, double as 16 digit hex

//Encoding values - json strings

#define enc_NONE  0x00  // do nothing just include data as is - ONLY cJSON_String!!!

#define enc_INT8  0x01  // put number into 1 unsigned byte field
#define enc_INT16 0x02  // ditto 2 bytes 
#define enc_INT32 0x04  // ditto 4 bytes
#define enc_INT64 0x08  // bitto 8 bytes

#define enc_TOKEN 0x10  // use custom lookup token (256 to choose from)
#define enc_HEX85 0xF1  // re-encode HEX as ASCII 85

#define enc_FLT   0x40  // put into a float (4 bytes - signed)
#define enc_DBL   0x80  // put into a double (8 bytes - signed)
#define enc_CROP  0xFF  // REMOVE THE FIELD

#define ENC_BYTES_MAX 160

#ifndef V17VERBOSE
#define V17VERBOSE 0
#endif

#define V17DO if(V17VERBOSE)

// this is hex
// first two byte is the content field
// this allows for 64 known fields to be encoded.
#define ENC_MASK "0000"
#define ENC_JSON_NAME "A1"  // we will change this for different versions...

// This tells the encode/decoder how to treat a json field
// ** DO NOT CHANGE THE ORDER OF THIS ARRAY **
// ** WITHOUT VERSIONING THE MESSAGE **
///** ADDING NEW ITEMS TO THE END DOES NOT NEED A NEW VERSION **
struct {
    char* name;
    unsigned int mask;
    unsigned char enctype;
    unsigned char jsontype;
} json_map[] = {
    {"coin", 0x0001, enc_NONE, cJSON_String},
    {"coinaddr",0x0002, enc_NONE, cJSON_String},
    {"cointxid",0x0004, enc_HEX85, cJSON_String},
    {"amount",0x0008, enc_DBL, cJSON_String},
    {"coinv",0x0010,enc_INT16, cJSON_Number},

    {0,0,0} // end-of-list
};

// Custom token list of upto 256 tokens 
struct {
    char* name;
    unsigned char value;
} enc_token[] = {

    {0,0} // end-of-list
};


union value64_t {
    int64_t integer;
    double	real;
};

union value32_t {
    int32_t integer;
    float real;
};

//encode v17 msg into original json
cJSON* v17encode(cJSON* in_json) {
    cJSON* ret_json;

//  need to get number of elements in json array
    int json_cnt=cJSON_GetArraySize(in_json);
    unsigned int encMASK=0;
    char encBytes[2*ENC_BYTES_MAX];
    char workBytes[2*ENC_BYTES_MAX];
    union value64_t value64;
    union value32_t value32;

    if(!json_cnt) return in_json; // got no json items to process
//  initialise the array
    strcpy(encBytes, ENC_MASK);
    size_t enc_len=strlen(encBytes);
    
    for(int i=0, t,l,n; json_map[i].name; i++) { // this loop must be same in encoder and decoder
	    cJSON *json_item=cJSON_GetObjectItem(in_json, json_map[i].name);
        if(json_item) {
            json_cnt-=1;
            encMASK |= json_map[i].mask; // register the json item.
            switch (json_map[i].enctype) {
                case enc_INT8:
                    if(json_map[i].jsontype==cJSON_Number)
                        sprintf((encBytes+enc_len),"%02x",(unsigned char)json_item->valueint);
                    else sprintf((encBytes+enc_len),"%02x",(unsigned char)strtol(json_item->valuestring,0,0));
                    enc_len+=2;
                    break;
                case enc_INT16:
                    if(json_map[i].jsontype==cJSON_Number)
                        sprintf((encBytes+enc_len),"%04x",(uint16_t)json_item->valueint);
                    else sprintf((encBytes+enc_len),"%04x",(uint16_t)strtol(json_item->valuestring,0,0));
                    enc_len+=4;
                    break;
                case enc_INT32:
                    if(json_map[i].jsontype==cJSON_Number)
                        sprintf((encBytes+enc_len),"%08x",(uint32_t)json_item->valueint);
                    else sprintf((encBytes+enc_len),"%08x",(uint32_t)strtol(json_item->valuestring,0,0));
                    enc_len+=8;
                    break;
                case enc_INT64:
                    if (json_map[i].jsontype==cJSON_Number)
                        sprintf((encBytes+enc_len),"%016lx",(uint64_t)json_item->valueint);
                    else sprintf((encBytes+enc_len),"%016lx",(uint64_t)strtol(json_item->valuestring,0,0));
                    enc_len+=16;
                    break;
                case enc_TOKEN:
                    for(t=0;enc_token[t].name;t++) {
                        if(!strcmp(enc_token[t].name, json_item->valuestring)) {
                            sprintf((encBytes+enc_len),"%02x",enc_token[t].value);
                            enc_len+=2;
                            break;
                        }
                    }
                    if(enc_token[t].name==0) return in_json; //cannot encode token not understood
                    break;
                case enc_FLT:
                    if(json_map[i].jsontype==cJSON_Number)
                        value32.real=json_item->valuedouble;
                    else value32.real=atof(json_item->valuestring);
                    sprintf((encBytes+enc_len),"%08x",value32.integer);
                    enc_len+=8;
                    break;
                case enc_DBL:
                    if(json_map[i].enctype==cJSON_Number)
                        value64.real=json_item->valuedouble;
                    else value64.real=atof(json_item->valuestring);
                    sprintf((encBytes+enc_len),"%016lx",value64.integer);
                    enc_len+=16;
                    break;
                case enc_HEX85:
                    // +1 adjusts for inclusion of original string length in binary buffer - need this so can recover string.
                    n=hexstr2bytes(json_item->valuestring, (unsigned char*)workBytes+1, sizeof(workBytes)-1)+1;
                    workBytes[0]=strlen(json_item->valuestring); // store original length of string.
                    if (n!=1) {
                        char hex85bytes[sizeof(workBytes)];
                        if (n%4) { // if bytes not divisible by 4 - pad it out
                            int rem=n%4; n=n+4-rem;
                            if ( n> sizeof(workBytes)) return in_json; // too long cant encode
                        }
                        l=Z85_encode((byte*)workBytes, n, (byte*)hex85bytes, sizeof(hex85bytes));
                        if(l>0xff) return in_json; // 255 char max
                        sprintf((encBytes+enc_len),"%02x",l);
                        enc_len+=2;
                        strcat(encBytes,hex85bytes);
                        enc_len+=l;
                        break;
                    } else {
                        return in_json; // hex85 encoding failed
                    }
                case enc_NONE:
                    l = strlen(json_item->valuestring);
                    if(l>0xff) return in_json; // 255 char max
                    sprintf((encBytes+enc_len),"%02x",l);
                    enc_len+=2;
                    strcat(encBytes,json_item->valuestring);
                    enc_len+=l;
                    break;
           }
        }
    }
    if(json_cnt) return in_json; // cannot encode - some json not processed.

    if(strlen(encBytes)>ENC_BYTES_MAX) return in_json; // encoding too long
    
//  Put the content mask into the string for the decoder.
    sprintf(workBytes,"%04x",encMASK);
    strncpy(encBytes,workBytes,4);
    
//  if we are here then construct new JSON string containing compressed message
    ret_json=cJSON_CreateObject();
    cJSON_AddStringToObject(ret_json, ENC_JSON_NAME, encBytes);
    
    cJSON_Delete(in_json); // destroy original json
    return ret_json;
}

//decode jssn msg into shorter v17 msg format
cJSON* v17decode(cJSON* in_json) {
    cJSON* ret_json;
    unsigned int encMask=0;
    int enc_len=0;
    char valuestring[ENC_BYTES_MAX*2];
    char workBytes[ENC_BYTES_MAX*2];
    union value32_t value32;
    union value64_t value64;
    
    cJSON *mgw_json=cJSON_GetObjectItem(in_json,ENC_JSON_NAME);
    
    if(!mgw_json) {
        V17DO printf("NOT MGW JSON\n");
        return in_json; // its not our json
    }
    char *v7_json=mgw_json->valuestring;
    if(!v7_json) return in_json; // nothing to do
    sscanf(v7_json,"%04x",&encMask);
 
    enc_len+=4;
    ret_json=cJSON_CreateObject(); // need to delete on all error paths...

    V17DO printf("Decoding...\n");
    for (int i=0, n ; json_map[i].name; i++) { // this loop has to be the same in encoder/decoder
        if(json_map[i].mask&encMask) {
            V17DO printf("Expecting %s,", json_map[i].name);
            switch (json_map[i].enctype) {
                    int int8_value;
                    int int16_value;
                case enc_INT8:
                    sscanf((v7_json+enc_len),"%02x",&int8_value);
                    V17DO printf("found %d\n",int8_value);
                    if(json_map[i].jsontype==cJSON_Number)
                        cJSON_AddNumberToObject(ret_json, json_map[i].name, int8_value);
                    else {
                        sprintf(valuestring,"%d",int8_value);
                        cJSON_AddStringToObject(ret_json, json_map[i].name, valuestring);
                    }
                    enc_len+=2;
                    break;
                case enc_INT16:
                    sscanf((v7_json+enc_len),"%04x",&int16_value);
                    V17DO printf("found %d\n", int16_value);
                    if(json_map[i].jsontype==cJSON_Number)
                        cJSON_AddNumberToObject(ret_json, json_map[i].name, int16_value);
                    else {
                        sprintf(valuestring,"%d",int16_value);
                        cJSON_AddStringToObject(ret_json, json_map[i].name, valuestring);
                    }
                    enc_len+=4;
                    break;
                case enc_INT32:
                    sscanf((v7_json+enc_len),"%08x",&value32.integer);
                    V17DO printf("found %d\n", value32.integer);
                    if(json_map[i].jsontype==cJSON_Number)
                        cJSON_AddNumberToObject(ret_json, json_map[i].name, value32.integer);
                    else {
                        sprintf(valuestring,"%d",value32.integer);
                        cJSON_AddStringToObject(ret_json, json_map[i].name, valuestring);
                    }
                    enc_len+=8;
                    break;
                case enc_INT64:
                    sscanf((v7_json+enc_len),"%016lx",&value64.integer);
                    V17DO printf("found %ld\n", value64.integer);
                    if(json_map[i].jsontype==cJSON_Number)
                        cJSON_AddNumberToObject(ret_json, json_map[i].name, value64.integer);
                    else {
                        sprintf(valuestring,"%ld",value64.integer);
                        cJSON_AddStringToObject(ret_json, json_map[i].name, valuestring);
                    }
                    enc_len+=16;
                    break;
                case enc_TOKEN:
                    sscanf((v7_json+enc_len),"%02x",&value32.integer);
                    enc_len+=2;
                    for(int t=0;enc_token[t].name;t++) {
                        if(enc_token[t].value==value32.integer) {
                            V17DO printf("found %s\n", enc_token[t].name);
                            cJSON_AddStringToObject(ret_json, json_map[i].name, enc_token[t].name);
                            break;
                        }
                    }
                    break;
                case enc_FLT:
                    sscanf((v7_json+enc_len),"%08x",&value32.integer);
                    V17DO printf("found %.8f\n", value32.real);
                    if(json_map[i].jsontype==cJSON_Number)
                        cJSON_AddNumberToObject(ret_json, json_map[i].name, value32.real);
                    else {
                        sprintf(valuestring,"%.8f",value32.real);
                        cJSON_AddStringToObject(ret_json, json_map[i].name, valuestring);
                    }
                    enc_len+=8;
                    break;
                case enc_DBL:
                    sscanf((v7_json+enc_len),"%016lx",&value64.integer);
                    V17DO printf("found %.8f\n", value64.real);
                    if(json_map[i].jsontype==cJSON_Number)
                        cJSON_AddNumberToObject(ret_json, json_map[i].name, value64.real);
                    else {
                        sprintf(valuestring,"%.8f",value64.real);
                        cJSON_AddStringToObject(ret_json, json_map[i].name, valuestring);
                    }
                    enc_len+=16;
                    break;
                case enc_HEX85:
                    sscanf((v7_json+enc_len),"%02x",&value32.integer);
                    enc_len+=2;
                    strncpy(valuestring,(v7_json+enc_len), value32.integer);
                    valuestring[value32.integer]=0;
                    n=Z85_decode(valuestring, (byte*)workBytes, sizeof(workBytes));
                    enc_len+=value32.integer;
                    value32.integer=workBytes[0]; //recover original string length
                    if (n) {
                        if(bytes2hexstr((byte*)workBytes+1, n-1, valuestring, sizeof(valuestring))) {
                            valuestring[value32.integer]=0; // null terminate at original length
                            V17DO printf("found: %s\n", valuestring);
                            cJSON_AddStringToObject(ret_json,json_map[i].name,valuestring);
                        } else {
                            V17DO printf("FAILED: BIN->HEX: %s <- [%d]\"%s\"\n", json_map[i].name, value32.integer, valuestring);
                            cJSON_Delete(ret_json); return in_json; }  // hex85 decoding failed
                    } else {
                        V17DO printf("FAILED: B85->BIN: %s <- [%d]\"%s\"\n", json_map[i].name, value32.integer, valuestring);
                        cJSON_Delete(ret_json); return in_json; }// hex85 decoding failed
                    
                    break;
                case enc_NONE:
                    sscanf((v7_json+enc_len),"%02x",&value32.integer);
                    enc_len+=2;
                    strncpy(valuestring,(v7_json+enc_len),value32.integer);
                    enc_len+=value32.integer;
                    valuestring[value32.integer]=0;
                    V17DO printf("found %s\n", valuestring);
                    cJSON_AddStringToObject(ret_json, json_map[i].name, valuestring);
                    break;

            }
        }
    }
    return ret_json;
}


#endif //last line

