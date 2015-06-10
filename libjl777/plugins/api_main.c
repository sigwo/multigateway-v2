//
//  api_main.c
//  crypto777
//
//  Copyright (c) 2015 jl777. All rights reserved.
//
#include <stdint.h>
#include "ccgi.h"
#include "nn.h"
#include "cJSON.h"
#include "pipeline.h"
uint32_t _crc32(uint32_t crc,const void *buf,size_t size);
long _stripwhite(char *buf,int accept);
#define nn_errstr() nn_strerror(nn_errno())

void process_json(cJSON *json)
{
    int32_t pushsock,pullsock,i,len,checklen; uint32_t tag;
    char endpoint[128],*resultstr,*jsonstr,*apiendpoint = "ipc://SuperNET.api";
    jsonstr = cJSON_Print(json), _stripwhite(jsonstr,' ');
    printf("jsonstr.(%s)\r\n",jsonstr);
    len = (int32_t)strlen(jsonstr)+1;
    tag = _crc32(0,jsonstr,len);
    sprintf(endpoint,"ipc://api.%u",tag);
    free(jsonstr);
    cJSON_AddItemToObject(json,"apitag",cJSON_CreateString(endpoint));
    jsonstr = cJSON_Print(json), _stripwhite(jsonstr,' ');
    len = (int32_t)strlen(jsonstr)+1;
    printf("jsonstr.(%s)\r\n",jsonstr);
    if ( 1 && json != 0 )
    {
        if ( (pushsock= nn_socket(AF_SP,NN_PUSH)) >= 0 )
        {
            printf("pushsock.%d\r\n",pushsock);
            if ( nn_connect(pushsock,apiendpoint) < 0 )
                printf("error connecting to apiendpoint sock.%d type.%d (%s) %s\r\n",pushsock,NN_PUSH,apiendpoint,nn_errstr());
            else if ( (checklen= nn_send(pushsock,jsonstr,len,0)) != len )
                printf("checklen.%d != len.%d for nn_send to (%s)\r\n",checklen,len,apiendpoint);
            else
            {
                if ( (pullsock= nn_socket(AF_SP,NN_PULL)) >= 0 )
                {
                    if ( nn_bind(pullsock,endpoint) < 0 )
                        printf("error binding to sock.%d type.%d (%s) %s\r\n",pullsock,NN_PULL,endpoint,nn_errstr());
                    else
                    {
                        if ( nn_recv(pullsock,&resultstr,NN_MSG,0) > 0 )
                        {
                            printf("%s\r\n",resultstr);
                            nn_freemsg(resultstr);
                        } else printf("error getting results\r\n");
                    }
                    nn_shutdown(pullsock,0);
                } else printf("error getting pullsock\r\n");
                nn_shutdown(pushsock,0);
            }
        } else printf("error getting pushsock.%s\r\n",nn_errstr());
    }
    free(jsonstr);
}

int main(int argc, char **argv)
{
    CGI_varlist *varlist; const char *name; CGI_value  *value;  int i; cJSON *json;
    fputs("Content-type: text/plain\r\n\r\n", stdout);
    if ((varlist = CGI_get_all(0)) == 0) {
        printf("No CGI data received\r\n");
        return 0;
    }
    /* output all values of all variables and cookies */
    json = cJSON_CreateObject();
    for (name = CGI_first_name(varlist); name != 0; name = CGI_next_name(varlist))
    {
        value = CGI_lookup_all(varlist, 0);
        /* CGI_lookup_all(varlist, name) could also be used */
        for (i = 0; value[i] != 0; i++)
        {
            printf("%s [%d] = %s\r\n", name, i, value[i]);
            if ( i == 0 )
                cJSON_AddItemToObject(json,name,cJSON_CreateString(value[i]));
        }
    }
    CGI_free_varlist(varlist);
    process_json(json);
    return 0;
}

