//
//  plugins.c
//  SuperNET API extension
//

#include <stdio.h>
#include <string.h>
#include "nn.h"
#include "bus.h"

int32_t process_plugin_json(char *retbuf,long max,char *jsonstr)
{
    retbuf[max-1] = 0;
    strncpy(retbuf,jsonstr,max-1);
    return(strlen(retbuf));
}

int32_t init_daemonsock(uint64_t daemonid,int32_t timeoutmillis)
{
    int32_t sock,err;
    char addr[MAX_JSON_FIELD];
    sprintf(addr,"ipc://%llu",(long long)daemonid);
    if ( (sock= nn_socket(AF_SP,NN_BUS)) < 0 )
    {
        printf("error %d nn_socket err.%s\n",sock,nn_strerror(nn_errno()));
        return(-1);
    }
    if ( (err= nn_bind(sock,addr)) < 0 )
    {
        printf("error %d nn_bind.%d (%s) | %s\n",err,sock,addr,nn_strerror(nn_errno()));
        return(-1);
    }
    nn_setsockopt(sock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeoutmillis,sizeof(timeoutmillis));
    sprintf(addr,"ipc://%llu",(long long)daemonid ^ 1);
    if ( (err= nn_connect(sock,addr)) < 0 )
    {
        printf("error %d nn_connect err.%s (%llu to %s)\n",sock,nn_strerror(nn_errno()),(long long)daemonid,addr);
        return(-1);
    }
    printf("daemonsock: %d nn_connect (%llu <-> %s)\n",sock,(long long)daemonid,addr);
    return(sock);
}

int main(int argc,const char *argv[])
{
    uint64_t daemonid;
    int32_t sock,len;
    char retbuf[8192],*jsonstr,*retstr;
    if ( argc < 2 )
    {
        printf("usage: %s <daemonid>\n",argv[0]);
        return(-1);
    }
    daemonid = atol(argv[1]);
    if ( (sock= init_daemonsock(daemonid,100)) >= 0 )
    {
        while ( 1 )
        {
            if ( (len= nn_recv(sock,&jsonstr,NN_MSG,0)) > 0 )
            {
                printf ("RECEIVED (%s).%d FROM BUS -> daemonid.%llu\n",jsonstr,len,(long long)daemonid);
                if ( (len= process_plugin_json(retbuf,sizeof(retbuf),jsonstr)) > 0 )
                    nn_send(sock,retbuf,len,0));
            }
        }
        nn_shutdown(sock);
    }
    return(0);
}

