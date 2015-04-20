//
//  echodemo.c
//  SuperNET API extension example plugin
//

//#define GLOBAL_TRANSPORT // define if endpoint should be globally accessible
//#define BUNDLED // define if bundled into SuperNET

#define PLUGINSTR "echo"
#define PLUGNAME(NAME) echo ## NAME
#define STRUCTNAME struct PLUGNAME(_info) //echo_info
#define STRINGIFY(NAME) #NAME
#define PLUGIN_EXTRASIZE sizeof(STRUCTNAME)

#define DEFINES_ONLY
#include "plugin777.c"
#undef DEFINES_ONLY

STRUCTNAME
{
    // this will be at the end of the plugins structure and will be called with all zeros to _init
};
char *PLUGNAME(_methods)[] = { "echo", "echo2" }; // list of supported methods

uint64_t PLUGNAME(_init)(struct plugin_info *plugin,STRUCTNAME *data)
{
    uint64_t disableflags = 0;
    printf("init %s size.%ld\n",plugin->name,sizeof(struct echo_info));
    // runtime specific state can be created and put into *data
    return(disableflags); // set bits corresponding to array position in _methods[]
}

int32_t PLUGNAME(_process_json)(struct plugin_info *plugin,char *retbuf,int32_t maxlen,char *jsonstr,cJSON *json,int32_t initflag)
{
    char *str;
    retbuf[0] = 0;
    printf("process %s (%s)\n",plugin->name,jsonstr);
    if ( initflag > 0 )
    {
        // configure settings
    }
    else
    {
        str = stringifyM(jsonstr);
        sprintf(retbuf,"{\"args\":%s,\"milliseconds\":%f,\"onetime\":%d}\n",str,milliseconds(),initflag < 0);
        free(str);
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
