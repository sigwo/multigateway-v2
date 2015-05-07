//
//  echodemo.c
//  SuperNET API extension example plugin
//  crypto777
//
//  Copyright (c) 2015 jl777. All rights reserved.
//

#define BUNDLED
#define PLUGINSTR "MGW"
#define PLUGNAME(NAME) MGW ## NAME
#define STRUCTNAME struct PLUGNAME(_info)
#define STRINGIFY(NAME) #NAME
#define PLUGIN_EXTRASIZE sizeof(STRUCTNAME)

#define DEFINES_ONLY
#include "../plugin777.c"
#include "storage.c"
#include "system777.c"
#undef DEFINES_ONLY

void MGW_idle(struct plugin_info *plugin) {}

STRUCTNAME MGW;
char *PLUGNAME(_methods)[] = { "myacctpubkeys" }; // list of supported methods

uint64_t PLUGNAME(_register)(struct plugin_info *plugin,STRUCTNAME *data,cJSON *json)
{
    uint64_t disableflags = 0;
    printf("init %s size.%ld\n",plugin->name,sizeof(struct MGW_info));
    return(disableflags); // set bits corresponding to array position in _methods[]
}

int32_t process_acctpubkeys(char *retbuf,char *jsonstr,cJSON *json)
{
    int32_t add_NXT_coininfo(uint64_t srvbits,uint64_t nxt64bits,char *coinstr,char *acctcoinaddr,char *pubkey);
    cJSON *item,*array; uint64_t gatewaybits; int32_t i,n=0,gatewayid,updated = 0;
    char gatewayNXT[MAX_JSON_FIELD],NXTaddr[MAX_JSON_FIELD],coinaddr[MAX_JSON_FIELD],pubkey[MAX_JSON_FIELD],coinstr[MAX_JSON_FIELD];
    copy_cJSON(gatewayNXT,cJSON_GetObjectItem(item,"NXT"));
    copy_cJSON(coinstr,cJSON_GetObjectItem(item,"coin"));
    gatewayid = get_API_int(cJSON_GetObjectItem(item,"gatewayid"),-1);
    gatewaybits = calc_nxt64bits(gatewayNXT);
    if ( (array= cJSON_GetObjectItem(item,"pubkeys")) != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = cJSON_GetArrayItem(array,i);
            copy_cJSON(NXTaddr,cJSON_GetObjectItem(item,"NXT"));
            copy_cJSON(coinaddr,cJSON_GetObjectItem(item,"coinaddr"));
            copy_cJSON(pubkey,cJSON_GetObjectItem(item,"pubkey"));
            updated += add_NXT_coininfo(gatewaybits,calc_nxt64bits(NXTaddr),coinstr,coinaddr,pubkey);
        }
    }
    sprintf(retbuf,"{\"result\":\"success\",\"gatewayid\":%d,\"gatewayNXT\":\"%s\",\"coin\":\"%s\",\"updated\":%d,\"total\":%d}",gatewayid,gatewayNXT,coinstr,updated,n);
    printf("(%s)\n",retbuf);
    return(updated);
}

int32_t PLUGNAME(_process_json)(struct plugin_info *plugin,uint64_t tag,char *retbuf,int32_t maxlen,char *jsonstr,cJSON *json,int32_t initflag)
{
    char *resultstr,*coinstr,*methodstr,*retstr = 0;
    retbuf[0] = 0;
    printf("<<<<<<<<<<<< INSIDE PLUGIN! process %s\n",plugin->name);
    if ( initflag > 0 )
    {
        if ( DB_msigs == 0 )
            DB_msigs = db777_create(0,0,"msigs",0);
        if ( DB_NXTaccts == 0 )
            DB_NXTaccts = db777_create(0,0,"NXTacct",0);
        strcpy(retbuf,"{\"result\":\"return JSON init\"}");
        MGW.readyflag = 1;
        plugin->allowremote = 1;
    }
    else
    {
        if ( plugin_result(retbuf,json,tag) > 0 )
            return((int32_t)strlen(retbuf));
        resultstr = cJSON_str(cJSON_GetObjectItem(json,"result"));
        methodstr = cJSON_str(cJSON_GetObjectItem(json,"method"));
        coinstr = cJSON_str(cJSON_GetObjectItem(json,"coin"));
        if ( methodstr == 0 || methodstr[0] == 0 )
        {
            printf("(%s) has not method\n",jsonstr);
            return(0);
        }
        printf("MGW.(%s) for (%s)\n",methodstr,coinstr!=0?coinstr:"");
        if ( resultstr != 0 && strcmp(resultstr,"registered") == 0 )
        {
            plugin->registered = 1;
            strcpy(retbuf,"{\"result\":\"activated\"}");
        }
        else if ( strcmp(methodstr,"myacctpubkeys") == 0 )
            process_acctpubkeys(retbuf,jsonstr,json);
        if ( retstr != 0 )
        {
            strcpy(retbuf,retstr);
            free(retstr);
        }
    }
    return((int32_t)strlen(retbuf));
}

int32_t PLUGNAME(_shutdown)(struct plugin_info *plugin,int32_t retcode)
{
    if ( retcode == 0 )  // this means parent process died, otherwise _process_json returned negative value
    {
    }
    return(retcode);
}
#include "../plugin777.c"
