//
//  peers777.c
//  SuperNET API extension example plugin
//  crypto777
//
//  Copyright (c) 2015 jl777. All rights reserved.
//

#define BUNDLED
#define PLUGINSTR "peers"
#define PLUGNAME(NAME) peers ## NAME
#define STRUCTNAME struct PLUGNAME(_info) 
#define STRINGIFY(NAME) #NAME
#define PLUGIN_EXTRASIZE sizeof(STRUCTNAME)

#define DEFINES_ONLY
#include "plugin777.c"
#undef DEFINES_ONLY

void peers_idle(struct plugin_info *plugin) {}

STRUCTNAME PEERS;
char *PLUGNAME(_methods)[] = { "direct" }; // list of supported methods

uint64_t PLUGNAME(_register)(struct plugin_info *plugin,STRUCTNAME *data,cJSON *argjson)
{
    uint64_t disableflags = 0;
    //printf("init %s size.%ld\n",plugin->name,sizeof(struct peers_info));
    // runtime specific state can be created and put into *data
    return(disableflags); // set bits corresponding to array position in _methods[]
}

int32_t PLUGNAME(_process_json)(struct plugin_info *plugin,uint64_t tag,char *retbuf,int32_t maxlen,char *jsonstr,cJSON *json,int32_t initflag)
{
    char *resultstr,*methodstr,*ipaddr,*retstr,*myipaddr;
    retbuf[0] = 0;
    //printf("<<<<<<<<<<<< INSIDE PLUGIN! process %s (%s)\n",plugin->name,jsonstr);
    if ( initflag > 0 )
    {
        // configure settings
        PEERS.readyflag = 1;
        plugin->allowremote = 1;
        strcpy(retbuf,"{\"result\":\"initflag > 0\"}");
    }
    else
    {
        if ( plugin_result(retbuf,json,tag) > 0 )
            return((int32_t)strlen(retbuf));
        resultstr = cJSON_str(cJSON_GetObjectItem(json,"result"));
        methodstr = cJSON_str(cJSON_GetObjectItem(json,"method"));
        ipaddr = cJSON_str(cJSON_GetObjectItem(json,"ipaddr"));
        myipaddr = cJSON_str(cJSON_GetObjectItem(json,"myipaddr"));
        if ( methodstr == 0 || methodstr[0] == 0 )
        {
            printf("(%s) has not method\n",jsonstr);
            return(0);
        }
        if ( resultstr != 0 && strcmp(resultstr,"registered") == 0 )
        {
            plugin->registered = 1;
            strcpy(retbuf,"{\"result\":\"activated\"}");
        }
        else if ( strcmp(methodstr,"direct") == 0 )
        {
            char *nn_directconnect(char *ipaddr);
            if ( ipaddr != 0 && strcmp(ipaddr,SUPERNET.myipaddr) == 0 )
            {
                if ( (retstr= nn_directconnect(myipaddr)) != 0 )
                {
                    strcpy(retbuf,retstr);
                    free(retstr);
                }
            }
        }
        else strcpy(retbuf,"{\"error\":\"under construction\"}");
    }
    printf("PEERS.(%s) -> (%s)\n",jsonstr,retbuf);
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
