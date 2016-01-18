//
//  main.c
//  nxt v1.7 codec
//
//  Created by Ian Ravenscroft on 08/01/2016.
//  Copyright (c) 2016 SuperNET. All rights reserved.
//

#define V17VERBOSE 1
#include <stdio.h>
#include <stdlib.h>

#include "nxtv17codec.h"
#include "cJSON.h"

// spoof some jl777 functions we dont use to avoid linker errors
int64_t conv_floatstr(char *tmp) { return 0; }
int32_t safecopy(char *dest,char *src,long len) { return 0; }

int main(int argc, const char * argv[]) {
    cJSON *arg_json, *v17_json, *error_json;
    char *json_string, *error_string;   
    if(argc>1) {
        arg_json=cJSON_Parse(argv[1]);
        json_string=cJSON_PrintUnformatted(arg_json);
        if(json_string) printf("GOT: %s\n",json_string);
        else { printf("GOT: null\n"); return -1; }
        free(json_string);
        if(!cJSON_GetObjectItem(arg_json, ENC_JSON_NAME)) { // check if already encoded.
            v17_json=v17encode(arg_json);
            json_string=cJSON_PrintUnformatted(v17_json);
            printf("ENC: %s\n",json_string);
            free(json_string);
        } else {
            printf("ENC: Already encoded\n");
            v17_json=arg_json; arg_json=0;
        }
        if(arg_json==v17_json) { // it didnt change
            char *v17_text=cJSON_PrintUnformatted(v17_json);
            cJSON_Delete(v17_json);
            error_json=cJSON_CreateObject();
            cJSON_AddStringToObject(error_json,"error","could not encode");
            cJSON_AddStringToObject(error_json,"input", v17_text);
            error_string=cJSON_PrintUnformatted(error_json);
            printf("%s\n",error_string);
            free(error_string);
            free(v17_text);
            cJSON_Delete(error_json);
            return -1;
        }
        v17_json=v17decode(v17_json);
        json_string=cJSON_PrintUnformatted(v17_json);
        printf("DEC: %s\n",json_string);
        free(json_string);
        cJSON_Delete(v17_json);
   } else {
        error_json=cJSON_CreateObject();
        cJSON_AddStringToObject(error_json,"error","null input");
        error_string=cJSON_PrintUnformatted(error_json);
        printf("%s\n",error_string);
        free(error_string);
        cJSON_Delete(error_json);
       return -1;
    }
    return 0;
}
