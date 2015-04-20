//
//  plugin777.c
//  SuperNET API extension
//

#ifdef DEFINES_ONLY
#ifndef crypto777_plugin777_h
#define crypto777_plugin777_h

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <float.h>
#include <ctype.h>
#include "nn.h"
#include "bus.h"
#include "cJSON.h"
#include "system777.c"

struct plugin_info
{
    char bindaddr[64],connectaddr[64],ipaddr[64],name[64];
    uint64_t daemonid,myid;
    uint32_t permanentflag,ppid,transportid,extrasize,timeout,counter;
    int32_t sock;
    uint16_t port;
    uint8_t pluginspace[];
};

#endif
#else
#ifndef crypto777_plugin777_c
#define crypto777_plugin777_c

#ifndef crypto777_plugin777_h
#define DEFINES_ONLY
#include __BASE_FILE__
#undef DEFINES_ONLY
#endif


int32_t get_socket_status(int32_t sock,int32_t timeoutmillis)
{
    struct nn_pollfd pfd;
    int32_t rc;
    pfd.fd = sock;
    pfd.events = NN_POLLIN | NN_POLLOUT;
    if ( (rc= nn_poll(&pfd,1,timeoutmillis)) == 0 )
        return(pfd.revents);
    else return(-1);
}

int32_t get_newinput(int32_t permanentflag,char *line,int32_t max,int32_t sock,int32_t timeoutmillis)
{
    int32_t rc,len;
    char *jsonstr = 0;
    line[0] = 0;
    if ( (permanentflag != 0 || ((rc= get_socket_status(sock,timeoutmillis)) > 0 && (rc & NN_POLLIN) != 0)) && (len= nn_recv(sock,&jsonstr,NN_MSG,0)) > 0 )
    {
        strncpy(line,jsonstr,max-1);
        line[max-1] = 0;
        nn_freemsg(jsonstr);
    }
    else if ( permanentflag == 0 )
        getline777(line,max);
    return((int32_t)strlen(line));
}

int32_t init_daemonsock(int32_t permanentflag,char *addr,int32_t timeoutmillis)
{
    int32_t sock,err;
    if ( (sock= nn_socket(AF_SP,NN_BUS)) < 0 )
    {
        printf("error %d nn_socket err.%s\n",sock,nn_strerror(nn_errno()));
        return(-1);
    }
    if ( permanentflag == 0 )
    {
        if ( (err= nn_connect(sock,addr)) < 0 )
        {
            printf("error %d nn_connect err.%s (%s to %s)\n",sock,nn_strerror(nn_errno()),permanentflag != 0 ? "PERMANENT" : "WEBSOCKET",addr);
            return(-1);
        }
    }
    else
    {
        if ( (err= nn_bind(sock,addr)) < 0 )
        {
            printf("error %d nn_bind.%d (%s) | %s\n",err,sock,addr,nn_strerror(nn_errno()));
            return(-1);
        }
    }
    nn_setsockopt(sock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeoutmillis,sizeof(timeoutmillis));
    printf("daemonsock: %d nn_connect (%s <-> %s)\n",sock,permanentflag != 0 ? "PERMANENT" : "WEBSOCKET",addr);
    return(sock);
}

void append_stdfields(struct plugin_info *plugin,char *retbuf)
{
    sprintf(retbuf+strlen(retbuf)-1,",\"permanent\":%d,\"myid\":\"%llu\",\"plugin\":\"%s\",\"endpoint\":\"%s\",\"millis\":%f}",plugin->permanentflag,(long long)plugin->myid,plugin->name,plugin->bindaddr[0]!=0?plugin->bindaddr:plugin->connectaddr,milliseconds());
}

int32_t process_plugin_json(struct plugin_info *plugin,int32_t permanentflag,uint64_t daemonid,int32_t sock,uint64_t myid,char *retbuf,int32_t max,char *jsonstr)
{
    int32_t len = (int32_t)strlen(jsonstr);
    cJSON *json;
    uint64_t sender;
    retbuf[0] = 0;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (sender= get_API_nxt64bits(cJSON_GetObjectItem(json,"myid"))) != myid )
        {
            if ( sender == daemonid )
            {
                if ( (len= PLUGNAME(_process_json)(plugin,retbuf,max,jsonstr,json,0)) < 0 )
                    return(len);
            }
            else if ( sender != 0 )
                printf("process message from %llu: (%s)\n",(long long)sender,jsonstr), fflush(stdout);
        } else printf("gotack.(%s) %f\n",jsonstr,milliseconds()), fflush(stdout);
    }
    else
    {
        if ( jsonstr[len-1] == '\r' || jsonstr[len-1] == '\n' || jsonstr[len-1] == '\t' || jsonstr[len-1] == ' ' )
            jsonstr[--len] = 0;
        if ( strcmp(jsonstr,"getpeers") == 0 )
            sprintf(retbuf,"{\"pluginrequest\":\"SuperNET\",\"requestType\":\"getpeers\"}");
        else sprintf(retbuf,"{\"result\":\"unparseable\",\"message\":\"%s\"}",jsonstr);
    }
    append_stdfields(plugin,retbuf);
    return((int32_t)strlen(retbuf));
}

int32_t process_json(struct plugin_info *plugin,char *jsonargs,int32_t initflag)
{
    char retbuf[8192],ipaddr[MAX_JSON_FIELD],*jsonstr = 0;
    cJSON *json = 0;
    uint16_t port;
    int32_t retval = 0;
    if ( jsonargs != 0 )
    {
        json = cJSON_Parse(jsonargs);
        jsonstr = cJSON_Print(json);
        _stripwhite(jsonstr,' ');
    }
    if ( initflag > 0 && json != 0 )
    {
        if ( (port = get_API_int(cJSON_GetObjectItem(json,"port"),0)) != 0 )
        {
            copy_cJSON(ipaddr,cJSON_GetObjectItem(json,"ipaddr"));
            if ( ipaddr[0] != 0 )
                strcpy(plugin->ipaddr,ipaddr), plugin->port = port;
            fprintf(stderr,"Set ipaddr (%s:%d)\n",plugin->ipaddr,plugin->port);
        }
    }
    fprintf(stderr,"initflag.%d got jsonargs.(%p) %p %p\n",initflag,jsonargs,jsonstr,json);
    if ( jsonstr != 0 && json != 0 )
        retval = PLUGNAME(_process_json)(plugin,retbuf,sizeof(retbuf)-1,jsonstr,json,initflag);
    if ( jsonstr != 0 )
        free(jsonstr);
    if ( json != 0 )
        free_json(json);
    printf("%s\n",retbuf), fflush(stdout);
    return(retval);
}

int32_t registerAPI(struct plugin_info *plugin,char *retbuf,int32_t maxlen)
{
    cJSON *json,*array;
    char *jsonstr;
    int32_t i;
    uint64_t disableflags = 0;
    json = cJSON_CreateObject(), array = cJSON_CreateArray();
    retbuf[0] = 0;
    disableflags = PLUGNAME(_init)(plugin,(void *)plugin->pluginspace);
    for (i=0; i<(sizeof(PLUGNAME(_methods))/sizeof(*PLUGNAME(_methods))); i++)
    {
        if ( PLUGNAME(_methods)[i] == 0 || PLUGNAME(_methods)[i][0] == 0 )
            break;
        if ( ((1LL << i) & disableflags) == 0 )
            cJSON_AddItemToArray(array,cJSON_CreateString(PLUGNAME(_methods)[i]));
    }
    cJSON_AddItemToObject(json,"requestType",cJSON_CreateString("register"));
    cJSON_AddItemToObject(json,"methods",array);
    jsonstr = cJSON_Print(json), free_json(json);
    _stripwhite(jsonstr,' ');
    strcpy(retbuf,jsonstr), free(jsonstr);
    append_stdfields(plugin,retbuf);
    return((int32_t)strlen(retbuf));
}

void configure_plugin(struct plugin_info *plugin,char *jsonargs,int32_t initflag)
{
    if ( (plugin->extrasize= PLUGIN_EXTRASIZE) > 0 )
    {
        plugin = realloc(plugin,sizeof(*plugin) + plugin->extrasize);
        memset(plugin->pluginspace,0,plugin->extrasize);
    }
    process_json(plugin,jsonargs,initflag);
}

void set_transportaddr(char *addr,char *transportstr,char *ipaddr,uint64_t num)
{
    if ( ipaddr != 0 )
        sprintf(addr,"%s://%s:%llu",transportstr,ipaddr,(long long)num);
    else sprintf(addr,"%s://%llu",transportstr,(long long)num);
}

#ifdef GLOBAL_TRANSPORT
static char *globalstr = "tcp";
#else
char *globalstr = 0;
#endif

#ifdef BUNDLED
static char *transportstr = "inproc"; static int32_t transportid = 'T'; // internal threads
int32_t PLUGNAME(_main)
#else

static char *transportstr = "ipc"; static int32_t transportid = 'L'; // local

int32_t main
#endif
(int argc,const char *argv[])
{
    struct plugin_info *plugin = calloc(1,sizeof(*plugin));
    int32_t len = 0;
    char line[8192],retbuf[8192],*jsonargs,*addr;
    milliseconds();
    plugin->ppid = OS_getppid();
    strcpy(plugin->name,PLUGINSTR);
    fprintf(stderr,"%s (%s).argc%d parent PID.%d\n",plugin->name,argv[0],argc,plugin->ppid);
    plugin->timeout = 1;
    if ( argc <= 2 )
    {
        jsonargs = (argc > 1) ? (char *)argv[1]:"{}";
        configure_plugin(plugin,jsonargs,-1);
        //fprintf(stderr,"PLUGIN_RETURNS.[%s]\n",line), fflush(stdout);
        return(0);
    }
    randombytes((uint8_t *)&plugin->myid,sizeof(plugin->myid));
    plugin->permanentflag = atoi(argv[1]);
    plugin->daemonid = atol(argv[2]);
    if ( plugin->permanentflag != 0 && globalstr != 0 )
    {
        transportstr = globalstr;
        plugin->transportid = 'G';
        if ( plugin->ipaddr[0] == 0 )
            plugin->port = wait_for_myipaddr(plugin->ipaddr);
        addr = (plugin->permanentflag == 0 ? plugin->connectaddr : plugin->bindaddr);
        set_transportaddr(addr,transportstr,plugin->ipaddr,plugin->port + plugin->permanentflag);
    }
    else
    {
        addr = (plugin->permanentflag == 0 ? plugin->connectaddr : plugin->bindaddr);
        set_transportaddr(addr,transportstr,0,plugin->daemonid + plugin->permanentflag);
        plugin->transportid = transportid;
    }
    configure_plugin(plugin,(argc >= 3) ? (char *)argv[3] : 0,1);
    fprintf(stderr,"argc.%d: %s.(%s) myid.%llu daemonid.%llu args.(%s)\n",argc,plugin->permanentflag != 0 ? "PERMANENT" : "WEBSOCKET",addr,(long long)plugin->myid,(long long)plugin->daemonid,argc>=3?argv[3]:"");
    if ( (plugin->sock= init_daemonsock(plugin->permanentflag,addr,plugin->timeout)) >= 0 )
    {
        if ( registerAPI(plugin,retbuf,sizeof(retbuf)-1) > 0 && plugin->permanentflag != 0 ) // register supported API
            nn_send(plugin->sock,retbuf,len+1,0); // send the null terminator too
        while ( OS_getppid() == plugin->ppid )
        {
            if ( (len= get_newinput(plugin->permanentflag,line,sizeof(line),plugin->sock,plugin->timeout)) > 0 )
            {
                if ( line[len-1] == '\n' )
                    line[--len] = 0;
                plugin->counter++;
                printf("%d <<<<<<<<<<<<<< RECEIVED (%s).%d -> (%s) %s\n",plugin->counter,line,len,addr,plugin->permanentflag != 0 ? "PERMANENT" : "WEBSOCKET"), fflush(stdout);
                if ( (len= process_plugin_json(plugin,plugin->permanentflag,plugin->daemonid,plugin->sock,plugin->myid,retbuf,sizeof(retbuf)-1,line)) > 1 )
                {
                    printf("%s\n",retbuf), fflush(stdout);
                    nn_send(plugin->sock,retbuf,len+1,0); // send the null terminator too
                } else if ( len < 0 )
                    break;
            }
            len = 0;
            msleep(1);
        }
        PLUGNAME(_shutdown)(plugin,len); // rc == 0 -> parent process died
        nn_shutdown(plugin->sock,0);
        free(plugin);
        return(len);
    } else printf("{\"error\":\"couldnt create socket\"}"), fflush(stdout);
    free(plugin);
    return(-1);
}

#endif
#endif
