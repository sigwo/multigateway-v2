//
//  relays777.c
//  SuperNET API extension example plugin
//  crypto777
//
//  Copyright (c) 2015 jl777. All rights reserved.
//

#define BUNDLED
#define PLUGINSTR "relays"
#define PLUGNAME(NAME) relays ## NAME
#define STRUCTNAME struct PLUGNAME(_info) 
#define STRINGIFY(NAME) #NAME
#define PLUGIN_EXTRASIZE sizeof(STRUCTNAME)

#define DEFINES_ONLY
#include "plugin777.c"
#undef DEFINES_ONLY

void relays_idle(struct plugin_info *plugin) {}

STRUCTNAME RELAYS;
char *PLUGNAME(_methods)[] = { "list", "newrelays", "listpeers", "newpeers", "listpubs", "newpubs" }; // list of supported methods

uint64_t PLUGNAME(_register)(struct plugin_info *plugin,STRUCTNAME *data,cJSON *argjson)
{
    uint64_t disableflags = 0;
    //printf("init %s size.%ld\n",plugin->name,sizeof(struct relays_info));
    // runtime specific state can be created and put into *data
    return(disableflags); // set bits corresponding to array position in _methods[]
}

cJSON *Relays;

int32_t add_newrelay(char *hostname,char *jsonstr,cJSON *json)
{
    char endpoint[512]; int bussock;
    printf("newrelay.(%s) arrived\n",hostname);
    if ( hostname[0] == 0 || is_remote_access(hostname) == 0 )
    {
        printf("illegal hostname.(%s)\n",hostname);
        return(0);
    }
    if ( Relays == 0 )
        Relays = cJSON_CreateArray();
    /*if ( in_jsonarray(Relays,hostname) == 0 )
    {
        if ( SUPERNET.iamrelay != 0 && bussock >= 0 )//&& eligible_lbserver(hostname) != 0 )
        {
            set_endpointaddr(endpoint,hostname,SUPERNET.port,NN_BUS);
            if ( nn_connect(bussock,endpoint) < 0 )
                printf("error connecting bus to (%s)\n",endpoint);
            else
            {
                //if ( type != NN_BUS )
                {
                    nn_send(bussock,jsonstr,(int32_t)strlen(jsonstr)+1,0);
                    printf("send to bus.(%s)\n",jsonstr);
                }
                printf("connected bus to hostname.(%s)\n",hostname);
            }
        }
        cJSON_AddItemToArray(Relays,cJSON_CreateString(hostname));
        return(1);
    }*/
    return(0);
}

char *add_newrelays(cJSON *array)
{
    int32_t i,n,added = 0;
    char retstr[1024],*hostname;
    if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            hostname = cJSON_str(cJSON_GetArrayItem(array,i));
            if ( hostname != 0 && in_jsonarray(Relays,hostname) == 0 )
                cJSON_AddItemToArray(Relays,cJSON_CreateString(hostname)), added++;
        }
    }
    sprintf(retstr,"{\"result\":\"newrelays\",\"added\":%d}",added);
    return(clonestr(retstr));
}

uint32_t *get_myRelays(int32_t *nump)
{
    uint32_t *list = 0;
    int32_t i,n,nonz = 0;
    uint32_t ipbits;
    if ( Relays != 0 && (n= cJSON_GetArraySize(Relays)) > 0 )
    {
        list = calloc(1,sizeof(*list) * n);
        for (i=0; i<n; i++)
        {
            if ( (ipbits= (uint32_t)calc_ipbits(cJSON_str(cJSON_GetArrayItem(Relays,i)))) != 0 )
                list[nonz++] = ipbits;
        }
    }
    if ( (*nump= nonz) == 0 && list != 0 )
        free(list), list = 0;
    return(list);
}

int32_t find_ipbits(uint32_t *list,int32_t n,uint32_t ipbits)
{
    int32_t i;
    for (i=0; i<n; i++)
        if ( list[i] == ipbits )
            return(i);
    return(-1);
}

char *unmatched_jsonstr(uint32_t *list,int32_t n)
{
    cJSON *json,*array = 0;
    int32_t i,nonz = 0;
    char ipaddr[64],*retstr = 0;
    for (i=0; i<n; i++)
        if ( list[i] != 0 )
        {
            expand_ipbits(ipaddr,list[i]);
            cJSON_AddItemToArray(array,cJSON_CreateString(ipaddr));
            if ( nonz++ == 0 )
                array = cJSON_CreateArray();
        }
    if ( nonz > 0 )
    {
        json = cJSON_CreateObject();
        cJSON_AddItemToObject(json,"requestType",cJSON_CreateString("pushrelays"));
        cJSON_AddItemToObject(json,"relays",array);
        retstr = cJSON_Print(json);
        free_json(json);
        _stripwhite(retstr,' ');
    }
    return(retstr);
}

char *relays_jsonstr(char *jsonstr,cJSON *json)
{
    cJSON *retjson; char *retstr;
    if ( SUPERNET.iamrelay != 0 && SUPERNET.myipaddr[0] != 0 )
    {
        if ( Relays == 0 )
        {
            Relays = cJSON_CreateArray();
            cJSON_AddItemToArray(Relays,cJSON_CreateString(SUPERNET.myipaddr));
        }
        retjson = cJSON_CreateObject();
        cJSON_AddItemToObject(retjson,"relays",Relays);
        cJSON_AddItemToObject(retjson,"result",cJSON_CreateString("success"));
        cJSON_AddItemToObject(retjson,"from",cJSON_CreateString(SUPERNET.myipaddr));
        retstr = cJSON_Print(retjson);
        Relays = cJSON_DetachItemFromObject(retjson,"relays");
        free_json(retjson);
        return(retstr);
    }
    else return(0);
}

/*
 {
 if ( (json= cJSON_Parse(msg)) != 0 )
 {
 if ( (array= cJSON_GetObjectItem(json,"relays")) != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
 {
 if ( nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_SNDPRIO,&priority,sizeof(priority)) >= 0 )
 {
 for (i=0; i<n; i++)
 {
 if ( (relay= cJSON_str(cJSON_GetArrayItem(array,i))) != 0 && ismyaddress(relay) == 0 )
 {
 set_endpointaddr(endpoint,relay,SUPERNET.port,NN_REP);
 if ( eligible_lbserver(relay) != 0 && nn_connect(lbsock,endpoint) >= 0 )
 {
 //add_newrelay(bussock,NN_PUB,relay,jsonstr);
 printf("+%s ",endpoint);
 }
 }
 }
 }
 }
 free_json(json);
 jsonstr = clonestr(msg);
 }*/

int32_t PLUGNAME(_process_json)(struct plugin_info *plugin,uint64_t tag,char *retbuf,int32_t maxlen,char *jsonstr,cJSON *json,int32_t initflag)
{
    char *resultstr,*retstr,*methodstr,*hostname;
    retbuf[0] = 0;
    //printf("<<<<<<<<<<<< INSIDE PLUGIN! process %s (%s)\n",plugin->name,jsonstr);
    if ( initflag > 0 )
    {
        // configure settings
        RELAYS.readyflag = 1;
        plugin->allowremote = 1;
        strcpy(retbuf,"{\"result\":\"initflag > 0\"}");
    }
    else
    {
        if ( plugin_result(retbuf,json,tag) > 0 )
            return((int32_t)strlen(retbuf));
        resultstr = cJSON_str(cJSON_GetObjectItem(json,"result"));
        methodstr = cJSON_str(cJSON_GetObjectItem(json,"method"));
        if ( methodstr == 0 || methodstr[0] == 0 )
        {
            printf("(%s) has not method\n",jsonstr);
            return(0);
        }
        printf("RELAYS.(%s)\n",methodstr);
        if ( resultstr != 0 && strcmp(resultstr,"registered") == 0 )
        {
            plugin->registered = 1;
            strcpy(retbuf,"{\"result\":\"activated\"}");
        }
        else
        {
            if ( strcmp(methodstr,"newrelay") == 0 && (hostname= cJSON_str(cJSON_GetObjectItem(json,"hostname"))) != 0 )
            {
                if ( add_newrelay(hostname,jsonstr,json) > 0 )
                    strcpy(retbuf,"{\"result\":\"relay added\"}");
                else strcpy(retbuf,"{\"result\":\"relay already in list\"}");
            }
            else if ( strcmp(methodstr,"getrelays") == 0 )
            {
                if ( (retstr= relays_jsonstr(jsonstr,json)) != 0 )
                {
                    strcpy(retbuf,retstr);
                    free(retstr);
                }
            }
        }
        if ( (hostname= cJSON_str(cJSON_GetObjectItem(json,"iamrelay"))) != 0 )
            add_newrelay(hostname,jsonstr,json);
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
#include "plugin777.c"
