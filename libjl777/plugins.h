//
//  plugins.h
//
//  Created by jl777 on 16/4/15.
//  Copyright (c) 2015 jl777. All rights reserved.
//

#ifndef xcode_plugins_h
#define xcode_plugins_h

#include "nn.h"
#include "bus.h"
#include "pair.h"
#include "pubsub.h"
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>

#define DAEMONFREE_MARGIN_SECONDS 13

struct daemon_info
{
    struct queueitem DL;
    queue_t messages;
    char name[64],ipaddr[64],*cmd,*jsonargs;
    uint64_t daemonid,instanceids[256];
    cJSON *methodsjson;
    double lastsearch;
    int32_t (*daemonfunc)(struct daemon_info *dp,int32_t permanentflag,char *cmd,char *jsonargs);
    int32_t finished,daemonsock,websocket,pairsock,allowremote;
    uint16_t port;
} *Daemoninfos[1024]; int32_t Numdaemons;
queue_t DaemonQ;


void free_daemon_info(struct daemon_info *dp)
{
    if ( dp->cmd != 0 )
        free(dp->cmd);
    if ( dp->jsonargs != 0 )
        free(dp->jsonargs);
    if ( dp->methodsjson != 0 )
        free_json(dp->methodsjson);
    if ( dp->daemonsock >= 0 )
        nn_shutdown(dp->daemonsock,0);
    if ( dp->pairsock >= 0 )
        nn_shutdown(dp->pairsock,0);
    free(dp);
}

void update_Daemoninfos()
{
    static portable_mutex_t mutex; static int didinit;
    struct daemon_info *dp;
    int32_t i,n;
    if ( didinit == 0 )
        portable_mutex_init(&mutex), didinit = 1;
    portable_mutex_lock(&mutex);
    for (i=n=0; i<Numdaemons; i++)
    {
        if ( (dp= Daemoninfos[i]) != 0 )
        {
            if ( dp->finished != 0 && currentmilli > (dp->lastsearch + DAEMONFREE_MARGIN_SECONDS*1000) )
            {
                printf("daemon.%llu finished\n",(long long)dp->daemonid);
                Daemoninfos[i] = 0;
                free_daemon_info(dp);
            }
            else
            {
                if ( dp->finished != 0 )
                    printf("waiting for DAEMONFREE_MARGIN_SECONDS for %s.%llu\n",dp->name,(long long)dp->daemonid);
                if ( i != n )
                    Daemoninfos[n] = dp;
                n++;
            }
        }
    }
    Numdaemons = n;
    if ( (dp= queue_dequeue(&DaemonQ,0)) != 0 )
        Daemoninfos[Numdaemons++] = dp;
    portable_mutex_unlock(&mutex);
}

struct daemon_info *find_daemoninfo(int32_t *indp,char *name,uint64_t daemonid,uint64_t instanceid)
{
    int32_t i,j,n;
    struct daemon_info *dp = 0;
    *indp = -1;
    if ( Numdaemons > 0 )
    {
        for (i=0; i<Numdaemons; i++)
        {
            if ( (dp= Daemoninfos[i]) != 0 && ((daemonid != 0 && dp->daemonid == daemonid) || (name != 0 && name[0] != 0 && strcmp(name,dp->name) == 0)) )
            {
                n = (sizeof(dp->instanceids)/sizeof(*dp->instanceids));
                if ( instanceid != 0 )
                {
                    for (j=0; j<n; j++)
                        if ( dp->instanceids[j] == instanceid )
                        {
                            *indp = j;
                            break;
                        }
                }
                dp->lastsearch = milliseconds();
                return(dp);
            }
        }
    }
    return(0);
}

int32_t add_instanceid(struct daemon_info *dp,uint64_t instanceid)
{
    int32_t i;
    for (i=0; i<(sizeof(dp->instanceids)/sizeof(*dp->instanceids)); i++)
    {
        if ( dp->instanceids[i] == 0 )
        {
            dp->instanceids[i] = instanceid;
            return(1);
        }
        if ( dp->instanceids[i] == instanceid )
            return(0);
    }
    dp->instanceids[rand() % (sizeof(dp->instanceids)/sizeof(*dp->instanceids))] = instanceid;
    return(-1);
}

cJSON *instances_json(struct daemon_info *dp)
{
    cJSON *array = cJSON_CreateArray();
    char numstr[64];
    int32_t i;
    for (i=0; i<(sizeof(dp->instanceids)/sizeof(*dp->instanceids)); i++)
    {
        if ( dp->instanceids[i] != 0 )
            sprintf(numstr,"%llu",(long long)dp->instanceids[i]), cJSON_AddItemToArray(array,cJSON_CreateString(numstr));
    }
    return(array);
}

void connect_instanceid(struct daemon_info *dp,uint64_t instanceid,int32_t permanentflag)
{
    int32_t err;
    cJSON *json;
    char addr[64],numstr[64],*jsonstr;
    if ( permanentflag == 0 )
    {
        sprintf(addr,"ipc://%llu",(long long)instanceid);
        if ( (err= nn_connect(dp->daemonsock,addr)) < 0 )
        {
            printf("error %d nn_connect err.%s (%llu to %s)\n",dp->daemonsock,nn_strerror(nn_errno()),(long long)dp->daemonid,addr);
            return;
        }
        printf("connect_instanceid: %d nn_connect (%llu <-> %s)\n",dp->daemonsock,(long long)dp->daemonid,addr);
    }
    json = cJSON_CreateObject();
    cJSON_AddItemToObject(json,"requestType",cJSON_CreateString("instances"));
    cJSON_AddItemToObject(json,"instanceids",instances_json(dp));
    sprintf(numstr,"%llu",(long long)dp->daemonid), cJSON_AddItemToObject(json,"myid",cJSON_CreateString(numstr));
    jsonstr = cJSON_Print(json);
    stripwhite(jsonstr,strlen(jsonstr));
    free_json(json);
    nn_send(dp->daemonsock,jsonstr,strlen(jsonstr) + 1,0);
    free(jsonstr);
}

int32_t poll_daemons() // the only thread that is allowed to modify Daemoninfos[]
{
    static int counter=0;
    struct nn_pollfd pfd[sizeof(Daemoninfos)/sizeof(*Daemoninfos)];
    int32_t len,permflag,timeoutmillis,processed=0,rc,i,n = 0;
    char request[MAX_JSON_FIELD],*retstr,*str,*msg;
    uint64_t instanceid;
    struct daemon_info *dp;
    cJSON *json;
    timeoutmillis = 1;
    if ( Numdaemons > 0 )
    {
        counter++;
        memset(pfd,0,sizeof(pfd));
        for (i=0; i<Numdaemons; i++)
        {
            if ( (dp= Daemoninfos[i]) != 0 && dp->daemonsock >= 0 && dp->pairsock >= 0 && dp->finished == 0 )
            {
                pfd[i].fd = (counter & 1) == 0 ? dp->daemonsock : dp->pairsock;
                pfd[i].events = NN_POLLIN | NN_POLLOUT;
                n++;
            }
        }
        if ( n > 0 )
        {
            if ( (rc= nn_poll(pfd,Numdaemons,timeoutmillis)) > 0 )
            {
                for (i=0; i<Numdaemons; i++)
                {
                    if ( (pfd[i].revents & NN_POLLIN) != 0 )
                    {
                        if ( (dp= Daemoninfos[i]) != 0 && dp->finished == 0 )
                        {
                            if ( (len= nn_recv((counter & 1) == 0 ? dp->daemonsock : dp->pairsock,&msg,NN_MSG,0)) > 0 )
                            {
                                str = clonestr(msg);
                                nn_freemsg(msg);
                                processed++;
                                //if ( (counter % 1000) == 0 )
                                printf("%d %.6f >>>>>>>>>> RECEIVED.%d i.%d/%d (%s) FROM (%s) %llu\n",processed,milliseconds(),n,i,Numdaemons,str,dp->cmd,(long long)dp->daemonid);
                                //nn_send(dp->daemonsock,str,len,0);
                                nn_send(dp->pairsock,str,len,0);
                                if ( (json= cJSON_Parse(str)) != 0 )
                                {
                                    permflag = get_API_int(cJSON_GetObjectItem(json,"perm"),0);
                                    if ( permflag == 0 && (instanceid= get_API_nxt64bits(cJSON_GetObjectItem(json,"myid"))) != 0 )
                                    {
                                        if ( add_instanceid(dp,instanceid) != 0 )
                                            connect_instanceid(dp,instanceid,permflag);
                                    }
                                    copy_cJSON(request,cJSON_GetObjectItem(json,"pluginrequest"));
                                    if ( strcmp(request,"SuperNET") == 0 )
                                    {
                                        char *call_SuperNET_JSON(char *JSONstr);
                                        if ( (retstr= call_SuperNET_JSON(str)) != 0 )
                                        {
                                            //nn_send(dp->daemonsock,retstr,(int32_t)strlen(retstr)+1,0);
                                            nn_send(dp->pairsock,retstr,(int32_t)strlen(retstr)+1,0);
                                            free(retstr);
                                        }
                                    }
                                } else printf("parse error.(%s)\n",str);
                                if ( dp->websocket == 0 )
                                    queue_enqueue("daemon",&dp->messages,queueitem(str));
                            }
                        }
                    }
                }
            }
            else if ( rc < 0 )
                printf("Error polling daemons.%d\n",rc);
        }
    }
    update_Daemoninfos();
    return(processed);
}

int32_t call_system(struct daemon_info *dp,int32_t permanentflag,char *cmd,char *jsonargs)
{
    char *args[8],cmdstr[1024],daemonstr[64],portstr[8192],flagstr[3];
    int32_t i,n = 0;
    if ( dp == 0 )
    {
        if ( jsonargs != 0 && jsonargs[0] != 0 )
        {
            sprintf(cmdstr,"%s \"%s\"",cmd,jsonargs);
            //printf("SYSTEM.(%s)\n",cmdstr);
            system(os_compatible_path(cmdstr));
        }
        else system(os_compatible_path(cmd));
        return(0);
    } else cmd = dp->cmd;
    memset(args,0,sizeof(args));
    if ( dp->websocket != 0 && permanentflag == 0 )
    {
        args[n++] = WEBSOCKETD;
        sprintf(portstr,"--port=%d",dp->websocket), args[n++] = portstr;
        if ( Debuglevel > 0 )
            args[n++] = "--devconsole";
    }
    args[n++] = dp->cmd;
    for (i=1; cmd[i]!=0; i++)
        if ( cmd[i] == ' ' )
            break;
    if ( cmd[i] != 0 && cmd[i+1] != 0 )
        cmd[i] = 0, args[n++] = &cmd[i+1];
    sprintf(flagstr,"%d",permanentflag);
    args[n++] = flagstr;
    if ( dp->daemonid != 0 )
    {
        sprintf(daemonstr,"%llu",(long long)dp->daemonid);
        args[n++] = daemonstr;
    }
    if ( dp->jsonargs != 0 && dp->jsonargs[0] != 0 )
        args[n++] = dp->jsonargs;
    args[n++] = 0;
    return(OS_launch_process(args));
}

/*
int32_t init_daemonsock(int32_t permanentflag,uint64_t daemonid)
{
    int32_t sock,err,to = 1;
    char addr[64];
    sprintf(addr,"ipc://%llu",(long long)daemonid + permanentflag*2);
    printf("init_daemonsocks %s\n",addr);
    if ( (sock= nn_socket(AF_SP,(permanentflag == 0) ? NN_BUS : NN_BUS)) < 0 )
    {
        printf("error %d nn_socket err.%s\n",sock,nn_strerror(nn_errno()));
        return(-1);
    }
    if ( (err= nn_bind(sock,addr)) < 0 )
    {
        printf("error %d nn_bind.%d (%s) | %s\n",err,sock,addr,nn_strerror(nn_errno()));
        return(-1);
    }
    if ( permanentflag != 0 )
    {
        sprintf(addr,"ipc://%llu",(long long)daemonid + 1);
        if ( (err= nn_connect(sock,addr)) < 0 )
        {
            printf("error %d nn_connect err.%s (%llu to %s)\n",sock,nn_strerror(nn_errno()),(long long)daemonid,addr);
            return(-1);
        }
    }
    assert(nn_setsockopt(sock,NN_SOL_SOCKET,NN_RCVTIMEO,&to,sizeof (to)) >= 0);
    return(sock);
}*/
int32_t init_daemonsock(int32_t permanentflag,char *bindaddr,char *connectaddr)
{
    int32_t sock,err,to = 1;
    //char addr[64];
    //sprintf(addr,"ipc://%llu",(long long)daemonid + permanentflag*2);
    printf("<<<<<<<<<<<<< init_daemonsocks bind.(%s) connect.(%s)\n",bindaddr,connectaddr);
    if ( (sock= nn_socket(AF_SP,(permanentflag == 0) ? NN_BUS : NN_BUS)) < 0 )
    {
        printf("error %d nn_socket err.%s\n",sock,nn_strerror(nn_errno()));
        return(-1);
    }
    if ( (err= nn_bind(sock,bindaddr)) < 0 )
    {
        printf("error %d nn_bind.%d (%s) | %s\n",err,sock,bindaddr,nn_strerror(nn_errno()));
        return(-1);
    }
    /*if ( (err= nn_connect(sock,bindaddr)) < 0 )
    {
        printf("error %d nn_connect err.%s (%s)\n",sock,nn_strerror(nn_errno()),connectaddr);
        return(-1);
    }*/
    //if ( permanentflag != 0 )
    {
        //sprintf(addr,"ipc://%llu",(long long)daemonid + 1);
        if ( (err= nn_connect(sock,connectaddr)) < 0 )
        {
            printf("error %d nn_connect err.%s (%s)\n",sock,nn_strerror(nn_errno()),connectaddr);
            return(-1);
        }
    }
    assert(nn_setsockopt(sock,NN_SOL_SOCKET,NN_RCVTIMEO,&to,sizeof (to)) >= 0);
    return(sock);
}

void set_transportaddr(char *addr,char *transportstr,char *ipaddr,uint64_t num)
{
    if ( ipaddr != 0 )
        sprintf(addr,"%s://%s:%llu",transportstr,ipaddr,(long long)num);
    else sprintf(addr,"%s://%llu",transportstr,(long long)num);
}

void set_bind_transport(char *bindaddr,int32_t bundledflag,int32_t permanentflag,char *ipaddr,uint16_t port,uint64_t daemonid)
{
    if ( ipaddr != 0 && ipaddr[0] != 0 && port != 0 )
        set_transportaddr(bindaddr,"tcp",ipaddr,port + 2*permanentflag);
    else set_transportaddr(bindaddr,(bundledflag != 0) ? "inproc" : "ipc",0,daemonid + 2*permanentflag);
}

void set_connect_transport(char *bindaddr,int32_t bundledflag,int32_t permanentflag,char *ipaddr,uint16_t port,uint64_t daemonid)
{
    if ( ipaddr != 0 && ipaddr[0] != 0 && port != 0 )
        set_transportaddr(bindaddr,"tcp",ipaddr,port + 1);
    else set_transportaddr(bindaddr,(bundledflag != 0) ? "inproc" : "ipc",0,daemonid + 1);
}

void *_daemon_loop(struct daemon_info *dp,int32_t permanentflag)
{
    char bindaddr[512],connectaddr[512];
    int32_t childpid,status,bundledflag,sock;
    bundledflag = is_bundled_plugin(dp->name);
    set_bind_transport(bindaddr,bundledflag,permanentflag,dp->ipaddr,dp->port,dp->daemonid);
    set_connect_transport(connectaddr,bundledflag,permanentflag,dp->ipaddr,dp->port,dp->daemonid);
    sock = init_daemonsock(permanentflag,bindaddr,connectaddr);
    if ( permanentflag != 0 )
        dp->daemonsock = sock;
    else dp->pairsock = sock;
    printf("<<<<<<<<<<<<<<<<<< %s plugin.(%s) bind.(%s) connect.(%s)\n",permanentflag!=0?"PERMANENT":"WEBSOCKETD",dp->name,bindaddr,connectaddr);
    childpid = (*dp->daemonfunc)(dp,permanentflag,0,0);
    OS_waitpid(childpid,&status,0);
    printf("daemonid.%llu (%s %s) finished child.%d status.%d\n",(long long)dp->daemonid,dp->cmd,dp->jsonargs!=0?dp->jsonargs:"",childpid,status);
    if ( permanentflag != 0 )
    {
        printf("daemonid.%llu (%s %s) finished\n",(long long)dp->daemonid,dp->cmd,dp->jsonargs!=0?dp->jsonargs:"");
        dp->finished = 1;
    }
    return(0);
}

void *daemon_loop(void *args)
{
    struct daemon_info *dp = args;
    return(_daemon_loop(dp,0));
}

void *daemon_loop2(void *args)
{
    struct daemon_info *dp = args;
    return(_daemon_loop(dp,1));
}

char *launch_daemon(char *plugin,char *ipaddr,uint16_t port,int32_t websocket,char *cmd,char *arg,int32_t (*daemonfunc)(struct daemon_info *dp,int32_t permanentflag,char *cmd,char *jsonargs))
{
    struct daemon_info *dp;
    char retbuf[1024];
    if ( Numdaemons >= sizeof(Daemoninfos)/sizeof(*Daemoninfos) )
        return(clonestr("{\"error\":\"too many daemons, cant create anymore\"}"));
    dp = calloc(1,sizeof(*dp));
    dp->port = port;
    if ( ipaddr != 0 )
        strcpy(dp->ipaddr,ipaddr);
    if ( plugin != 0 )
        strcpy(dp->name,plugin);
    dp->cmd = clonestr(cmd);
    dp->daemonid = (uint64_t)(milliseconds() * 1000000) & (~(uint64_t)3);
    dp->daemonsock = -1, dp->pairsock = -1;
    dp->jsonargs = (arg != 0 && arg[0] != 0) ? clonestr(arg) : 0;
    dp->daemonfunc = daemonfunc;
    dp->websocket = websocket;
    if ( portable_thread_create((void *)daemon_loop2,dp) == 0 || (websocket != 0 && portable_thread_create((void *)daemon_loop,dp) == 0) )
    {
        free_daemon_info(dp);
        return(clonestr("{\"error\":\"portable_thread_create couldnt create daemon\"}"));
    }
    queue_enqueue("DamonQ",&DaemonQ,&dp->DL);
    sprintf(retbuf,"{\"result\":\"launched\",\"daemonid\":\"%llu\"}\n",(long long)dp->daemonid);
    return(clonestr(retbuf));
 }

char *language_func(char *plugin,char *ipaddr,uint16_t port,int32_t websocket,int32_t launchflag,char *cmd,char *jsonargs,int32_t (*daemonfunc)(struct daemon_info *dp,int32_t permanentflag,char *cmd,char *jsonargs))
{
    char buffer[65536] = { 0 };
    int out_pipe[2],saved_stdout;
    if ( launchflag != 0 || websocket != 0 )
        return(launch_daemon(plugin,ipaddr,port,websocket,cmd,jsonargs,daemonfunc));
    saved_stdout = dup(STDOUT_FILENO);
    if( pipe(out_pipe) != 0 )
        return(clonestr("{\"error\":\"pipe creation error\"}"));
    dup2(out_pipe[1],STDOUT_FILENO);
    close(out_pipe[1]);
    (*daemonfunc)(0,0,cmd,jsonargs);
    fflush(stdout);
    read(out_pipe[0],buffer,sizeof(buffer)-1), buffer[sizeof(buffer)-1] = 0;
    dup2(saved_stdout,STDOUT_FILENO);
    return(clonestr(buffer));
}

char *checkmessages(char *NXTaddr,char *NXTACCTSECRET,char *name,uint64_t daemonid,uint64_t instanceid)
{
    char *msg,*retstr = 0;
    cJSON *array = 0,*json = 0;
    struct daemon_info *dp;
    int32_t i,ind;
    if ( (dp= find_daemoninfo(&ind,name,daemonid,instanceid)) != 0 )
    {
        for (i=0; i<10; i++)
        {
            if ( (msg= queue_dequeue(&dp->messages,1)) != 0 )
            {
                if ( json == 0 )
                    json = cJSON_CreateObject(), array = cJSON_CreateArray();
                cJSON_AddItemToArray(array,cJSON_CreateString(msg));
                free_queueitem(msg);
            }
        }
        if ( json == 0 )
            return(clonestr("{\"result\":\"no messages\",\"messages\":[]}"));
        else
        {
            cJSON_AddItemToObject(json,"result",cJSON_CreateString("daemon messages"));
            cJSON_AddItemToObject(json,"messages",array);
            retstr = cJSON_Print(json);
            free_json(json);
            return(retstr);
        }
    }
    return(clonestr("{\"error\":\"cant find daemonid\"}"));
}

char *checkmsg_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    char plugin[MAX_JSON_FIELD],*retstr = 0;
    uint64_t daemonid,instanceid;
    copy_cJSON(plugin,objs[0]);
    daemonid = get_API_nxt64bits(objs[1]);
    instanceid = get_API_nxt64bits(objs[2]);
    if ( is_remote_access(previpaddr) != 0 )
        return(0);
    if ( sender[0] != 0 && valid > 0 )
        retstr = checkmessages(sender,NXTACCTSECRET,plugin,daemonid,instanceid);
    else retstr = clonestr("{\"result\":\"invalid checkmessages request\"}");
    return(retstr);
}

int32_t send_to_daemon(char *name,uint64_t daemonid,uint64_t instanceid,char *jsonstr)
{
    struct daemon_info *dp;
    int32_t len,ind,sock;
    cJSON *json;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        free_json(json);
        if ( (dp= find_daemoninfo(&ind,name,daemonid,instanceid)) != 0 )
        {
            if ( (len= (int32_t)strlen(jsonstr)) > 0 )
            {
                sock = (instanceid == 0 || ind < 0) ? dp->daemonsock : dp->pairsock; // do we need point to point to wss?
                return(nn_send(sock,jsonstr,len + 1,0));
            }
            else printf("send_to_daemon: error jsonstr.(%s)\n",jsonstr);
        }
    }
    else printf("send_to_daemon: cant parse jsonstr.(%s)\n",jsonstr);
    return(-1);
}

char *plugin_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    char plugin[MAX_JSON_FIELD],method[MAX_JSON_FIELD];
    struct daemon_info *dp;
    uint64_t daemonid,instanceid;
    int32_t ind;
    copy_cJSON(plugin,objs[0]);
    daemonid = get_API_nxt64bits(objs[1]);
    instanceid = get_API_nxt64bits(objs[2]);
    copy_cJSON(method,objs[3]);
    if ( (dp= find_daemoninfo(&ind,plugin,daemonid,instanceid)) != 0 )
    {
        if ( dp->allowremote == 0 && is_remote_access(previpaddr) != 0 )
            return(clonestr("{\"error\":\"cant remote call plugins\"}"));
        else if ( in_jsonarray(dp->methodsjson,method) == 0 )
            return(clonestr("{\"error\":\"method not allowed by plugin\"}"));
        else if ( send_to_daemon(dp->name,daemonid,instanceid,origargstr) != 0 )
        {
            
            return(clonestr("{\"error\":\"method not allowed by plugin\"}"));
        }
        else return(clonestr("{\"result\":\"message sent to plugin\"}"));
    }
    return(clonestr("{\"error\":\"cant find plugin\"}"));
}

char *register_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    char plugin[MAX_JSON_FIELD],retbuf[1024],*methodstr;
    uint64_t daemonid,instanceid;
    struct daemon_info *dp;
    int32_t ind;
    if ( is_remote_access(previpaddr) != 0 )
        return(clonestr("{\"error\":\"cant remote register plugins\"}"));
    copy_cJSON(plugin,objs[0]);
    daemonid = get_API_nxt64bits(objs[1]);
    instanceid = get_API_nxt64bits(objs[2]);
    if ( (dp= find_daemoninfo(&ind,plugin,daemonid,instanceid)) != 0 )
    {
        if ( plugin[0] == 0 || strcmp(dp->name,plugin) == 0 )
        {
            if ( objs[3] != 0 )
            {
                dp->methodsjson = cJSON_Duplicate(objs[3],1);
                methodstr = cJSON_Print(dp->methodsjson);
            } else methodstr = clonestr("[]");
            dp->allowremote = get_API_int(objs[4],0);
            sprintf(retbuf,"{\"result\":\"registered\",\"plugin\":\"%s\",\"daemonid\":%llu,\"instanceid\":%llu,\"allowremote\":%d,\"methods\":%s}",plugin,(long long)daemonid,(long long)instanceid,dp->allowremote,methodstr);
            free(methodstr);
            return(clonestr(retbuf));
        } else return(clonestr("{\"error\":\"plugin name mismatch\"}"));
    }
    return(clonestr("{\"error\":\"cant register inactive plugin\"}"));
}

char *passthru_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    char hopNXTaddr[64],tagstr[MAX_JSON_FIELD],coinstr[MAX_JSON_FIELD],plugin[MAX_JSON_FIELD],method[MAX_JSON_FIELD],params[MAX_JSON_FIELD],*str2,*cmdstr,*retstr = 0;
    struct coin_info *cp = 0;
    uint64_t daemonid,instanceid;
    copy_cJSON(coinstr,objs[0]);
    copy_cJSON(method,objs[1]);
    if ( is_remote_access(previpaddr) != 0 )
    {
        if ( in_jsonarray(cJSON_GetObjectItem(MGWconf,"remote"),method) == 0 && in_jsonarray(cJSON_GetObjectItem(cp->json,"remote"),method) == 0 )
            return(0);
    }
    copy_cJSON(params,objs[2]);
    unstringify(params), stripwhite_ns(params,strlen(params));
    copy_cJSON(tagstr,objs[3]);
    copy_cJSON(plugin,objs[4]);
    daemonid = get_API_nxt64bits(objs[5]);
    instanceid = get_API_nxt64bits(objs[6]);
    printf("daemonid.%llu tag.(%s) passthru.(%s) %p method=%s [%s] plugin.(%s)\n",(long long)daemonid,tagstr,coinstr,cp,method,params,plugin);
    if ( sender[0] != 0 && valid > 0 )
    {
        if ( daemonid != 0 )
        {
            unstringify(params);
            send_to_daemon(plugin,daemonid,instanceid,params);
            return(clonestr("{\"result\":\"unstringified params sent to daemon\"}"));
        }
        else if ( (cp= get_coin_info(coinstr)) != 0 && method[0] != 0 )
            retstr = bitcoind_RPC(0,cp->name,cp->serverport,cp->userpass,method,params);
    }
    else retstr = clonestr("{\"error\":\"invalid passthru_func arguments\"}");
    if ( is_remote_access(previpaddr) != 0 )
    {
        cmdstr = malloc(strlen(retstr)+512);
        str2 = stringifyM(retstr);
        sprintf(cmdstr,"{\"requestType\":\"remote\",\"coin\":\"%s\",\"method\":\"%s\",\"tag\":\"%s\",\"result\":\"%s\"}",coinstr,method,tagstr,str2);
        free(str2);
        hopNXTaddr[0] = 0;
        retstr = send_tokenized_cmd(!prevent_queueing("passthru"),hopNXTaddr,0,NXTaddr,NXTACCTSECRET,cmdstr,sender);
        free(cmdstr);
    }
    return(retstr);
}

char *remote_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    if ( is_remote_access(previpaddr) == 0 )
        return(clonestr("{\"error\":\"cant remote locally\"}"));
    return(clonestr(origargstr));
}

char *syscall_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    char jsonargs[MAX_JSON_FIELD],syscall[MAX_JSON_FIELD],plugin[MAX_JSON_FIELD],ipaddr[MAX_JSON_FIELD],*jsonstr,*str;
    cJSON *json;
    int32_t launchflag,websocket;
    uint16_t port;
    copy_cJSON(syscall,objs[0]);
    launchflag = get_API_int(objs[1],0);
    websocket = get_API_int(objs[2],0);
    copy_cJSON(jsonargs,objs[3]);
    copy_cJSON(plugin,objs[4]);
    copy_cJSON(ipaddr,objs[5]);
    port = get_API_int(objs[6],0);
    //unstringify(jsonargs);
    if ( (json= cJSON_Parse(jsonargs)) != 0 )
    {
        jsonstr = cJSON_Print(json);
        free_json(json);
        str = stringifyM(jsonstr);
        strcpy(jsonargs,str);
        free(str);
        free(jsonstr);
        stripwhite_ns(jsonargs,strlen(jsonargs));
    }
    printf("websocket.%d launchflag.%d syscall.(%s) jsonargs.(%s) json.%p\n",websocket,launchflag,syscall,jsonargs,json);
    if ( is_remote_access(previpaddr) != 0 )
        return(0);
    return(language_func(plugin,ipaddr,port,websocket,launchflag,syscall,jsonargs,call_system));
}

#endif
