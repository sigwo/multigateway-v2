//
//  plugins.h
//
//  Created by jl777 on 16/4/15.
//  Copyright (c) 2015 jl777. All rights reserved.
//

#ifndef xcode_plugins_h
#define xcode_plugins_h

struct daemon_info
{
    queue_t messages;
    uint64_t daemonid;
    int32_t finished,dereferenced,daemonsock,isws;
    char *cmd,*arg;
    void (*daemonfunc)(char *cmd,char *arg,uint64_t daemonid);
} *Daemoninfos[1024]; int32_t Numdaemons;

struct daemon_info *find_daemoninfo(uint64_t daemonid)
{
    int32_t i;
    if ( Numdaemons > 0 )
    {
        for (i=0; i<Numdaemons; i++)
            if ( Daemoninfos[i]->daemonid == daemonid )
                return(Daemoninfos[i]);
    }
    return(0);
}

int32_t init_daemonsock(uint64_t daemonid)
{
    int32_t sock,err,to = 1;
    char addr[MAX_JSON_FIELD];
    sprintf(addr,"ipc://%llu",(long long)daemonid);
    printf("init_daemonsocks %s\n",addr);
    if ( (sock= nn_socket(AF_SP,NN_BUS)) < 0 )
    {
        printf("error %d nn_socket err.%s\n",sock,nn_strerror(nn_errno()));
        return(-1);
    }
    printf("got sock.%d\n",sock);
    if ( (err= nn_bind(sock,addr)) < 0 )
    {
        printf("error %d nn_bind.%d (%s) | %s\n",err,sock,addr,nn_strerror(nn_errno()));
        return(-1);
    }
    assert (nn_setsockopt(sock,NN_SOL_SOCKET,NN_RCVTIMEO,&to,sizeof (to)) >= 0);
    printf("bound\n");
    sprintf(addr,"ipc://%llu",(long long)daemonid ^ 1);
    if ( (err= nn_connect(sock,addr)) < 0 )
    {
        printf("error %d nn_connect err.%s (%llu to %s)\n",sock,nn_strerror(nn_errno()),(long long)daemonid,addr);
        return(-1);
    }
    return(sock);
}

int32_t send_to_daemon(uint64_t daemonid,char *jsonstr)
{
    int32_t len;
    cJSON *json;
    struct daemon_info *dp;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        free_json(json);
        if ( (dp= find_daemoninfo(daemonid)) != 0 )
        {
            if ( (len= (int32_t)strlen(jsonstr)) > 0 )
                return(nn_send(dp->daemonsock,jsonstr,len + 1,0));
            else printf("send_to_daemon: error jsonstr.(%s)\n",jsonstr);
        }
    }
    printf("send_to_daemon: cant parse jsonstr.(%s)\n",jsonstr);
    return(-1);
}

int32_t poll_daemons()
{
    struct nn_pollfd pfd[sizeof(Daemoninfos)/sizeof(*Daemoninfos)];
    int32_t flag,len,processed=0,rc,i,n = 0;
    struct daemon_info *dp;
    char *msg;
    if ( Numdaemons > 0 )
    {
        memset(pfd,0,sizeof(pfd));
        for (i=flag=0; i<Numdaemons; i++)
        {
            if ( (dp= Daemoninfos[i]) != 0 )
            {
                if ( dp->finished != 0 )
                {
                    printf("daemon.%llu finished\n",(long long)dp->daemonid);
                    Daemoninfos[i] = 0;
                    dp->dereferenced = 1;
                    flag++;
                }
                else
                {
                    pfd[i].fd = dp->daemonsock;
                    pfd[i].events = NN_POLLIN | NN_POLLOUT;
                    n++;
                }
            }
        }
        if ( n > 0 )
        {
            if ( (rc= nn_poll(pfd,n,1)) > 0 )
            {
                for (i=0; i<Numdaemons; i++)
                {
                    if ( (pfd[i].revents & NN_POLLIN) != 0 )
                    {
                        if ( (dp= Daemoninfos[i]) != 0 && dp->finished == 0 )
                        {
                            if ( (len= nn_recv(dp->daemonsock,&msg,NN_MSG,0)) > 0 )
                            {
                                printf ("RECEIVED (%s).%d FROM BUS -> (%s)\n",msg,len,dp->cmd);
                                queue_enqueue("daemon",&dp->messages,msg);
                            }
                            processed++;
                        }
                    }
                }
            }
            else if ( rc < 0 )
                printf("Error polling daemons.%d\n",rc);
        }
        if ( flag != 0 )
        {
            static portable_mutex_t mutex; static int didinit;
            printf("compact Daemoninfos as %d have finished\n",flag);
            if ( didinit == 0 )
                portable_mutex_init(&mutex), didinit = 1;
            portable_mutex_lock(&mutex);
            for (i=n=0; i<Numdaemons; i++)
                if ( (Daemons[n]= Daemons[i]) != 0 )
                    n++;
            Numdaemons = n;
            portable_mutex_unlock(&mutex);
        }
    }
    return(processed);
}

void *daemon_loop(void *args)
{
    struct daemon_info *dp = args;
    (*dp->daemonfunc)(dp->cmd,dp->arg,dp->daemonid);
    printf("daemonid.%llu (%s %s) finished\n",(long long)dp->daemonid,dp->cmd,dp->arg!=0?dp->arg:"");
    dp->finished = 1;
    while ( dp->dereferenced == 0 )
        sleep(1);
    printf("daemonid.%llu (%s %s) dereferenced\n",(long long)dp->daemonid,dp->cmd,dp->arg!=0?dp->arg:"");
    if ( dp->daemonsock >= 0 )
        nn_shutdown(dp->daemonsock,0);
    free(dp->cmd), free(dp->arg), free(dp);
    return(0);
}

char *launch_daemon(int32_t isws,char *cmd,char *arg,void (*daemonfunc)(char *cmd,char *fname,uint64_t daemonid))
{
    struct daemon_info *dp;
    char retbuf[1024];
    int32_t daemonsock;
    uint64_t daemonid;
    if ( Numdaemons >= sizeof(Daemoninfos)/sizeof(*Daemoninfos) )
        return(clonestr("{\"error\":\"too many daemons, cant create anymore\"}"));
    daemonid = (uint64_t)(milliseconds() * 1000000) & (~(uint64_t)1);
    if ( (daemonsock= init_daemonsock(daemonid ^ 1)) >= 0 )
    {
        dp = calloc(1,sizeof(*dp));
        dp->cmd = clonestr(cmd);
        dp->daemonid = daemonid;
        dp->daemonsock = daemonsock;
        dp->arg = (arg != 0) ? clonestr(arg) : 0;
        dp->daemonfunc = daemonfunc;
        dp->isws = 1;
        Daemoninfos[Numdaemons++] = dp;
        if ( portable_thread_create((void *)daemon_loop,dp) == 0 )
        {
            free(dp->cmd), free(dp->arg), free(dp);
            nn_shutdown(dp->daemonsock,0);
            return(clonestr("{\"error\":\"portable_thread_create couldnt create daemon\"}"));
        }
        sprintf(retbuf,"{\"result\":\"launched\",\"daemonid\":\"%llu\"}",(long long)dp->daemonid);
        return(clonestr(retbuf));
    }
    return(clonestr("{\"error\":\"cant open file to launch daemon\"}"));
}

char *language_func(int32_t isws,int32_t launchflag,char *cmd,char *fname,void (*daemonfunc)(char *cmd,char *fname,uint64_t daemonid))
{
    char buffer[MAX_LEN+1] = { 0 };
    int out_pipe[2];
    int saved_stdout;
    if ( launchflag != 0 )
        return(launch_daemon(isws,cmd,fname,daemonfunc));
    saved_stdout = dup(STDOUT_FILENO);
    if( pipe(out_pipe) != 0 )
        return(clonestr("{\"error\":\"pipe creation error\"}"));
    dup2(out_pipe[1], STDOUT_FILENO);
    close(out_pipe[1]);
    (*daemonfunc)(cmd,fname,0);
    fflush(stdout);
    read(out_pipe[0],buffer,MAX_LEN);
    dup2(saved_stdout,STDOUT_FILENO);
    return(clonestr(buffer));
}

char *checkmessages(char *NXTaddr,char *NXTACCTSECRET,uint64_t daemonid)
{
    char *msg,*retstr = 0;
    cJSON *array = 0,*json = 0;
    struct daemon_info *dp;
    int32_t i;
    if ( (dp= find_daemoninfo(daemonid)) != 0 )
    {
        for (i=0; i<10; i++)
        {
            if ( (msg= queue_dequeue(&dp->messages)) != 0 )
            {
                if ( json == 0 )
                    json = cJSON_CreateObject(), array = cJSON_CreateArray();
                cJSON_AddItemToArray(array,cJSON_CreateString(msg));
                nn_freemsg(msg);
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

int file_exists(char *filename)
{
    struct stat buffer;
    return(stat(filename,&buffer) == 0);
}

void call_python(char *cmd,char *fname,uint64_t daemonid)
{
    FILE *fp;
    if ( (fp= fopen(fname,"r")) != 0 )
    {
        Py_Initialize();
        PyRun_SimpleFile(fp,fname);
        Py_Finalize();
        fclose(fp);
    }
}

void call_system(char *cmd,char *arg,uint64_t daemonid)
{
    char cmdstr[MAX_JSON_FIELD];
    sprintf(cmdstr,"%s %llu %s",cmd,(long long)daemonid,arg!=0?arg:" ");
    printf("SYSTEM.(%s)\n",cmdstr);
    system(cmdstr);
}

char *checkmsg_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    char *retstr = 0;
    if ( is_remote_access(previpaddr) != 0 )
        return(0);
    if ( sender[0] != 0 && valid > 0 )
        retstr = checkmessages(sender,NXTACCTSECRET,get_API_nxt64bits(objs[0]));
    else retstr = clonestr("{\"result\":\"invalid checkmessages request\"}");
    return(retstr);
}

char *remote_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    if ( is_remote_access(previpaddr) == 0 )
        return(clonestr("{\"error\":\"cant remote locally\"}"));
    return(clonestr(origargstr));
}

char *passthru_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    char hopNXTaddr[64],tagstr[MAX_JSON_FIELD],coinstr[MAX_JSON_FIELD],method[MAX_JSON_FIELD],params[MAX_JSON_FIELD],*str2,*cmdstr,*retstr = 0;
    struct coin_info *cp = 0;
    copy_cJSON(coinstr,objs[0]);
    copy_cJSON(method,objs[1]);
    if ( coinstr[0] != 0 )
        cp = get_coin_info(coinstr);
    if ( is_remote_access(previpaddr) != 0 )
    {
        if ( in_jsonarray(cJSON_GetObjectItem(MGWconf,"remote"),method) == 0 && in_jsonarray(cJSON_GetObjectItem(cp->json,"remote"),method) == 0 )
            return(0);
    }
    copy_cJSON(params,objs[2]);
    unstringify(params);
    copy_cJSON(tagstr,objs[3]);
    printf("tag.(%s) passthru.(%s) %p method=%s [%s]\n",tagstr,coinstr,cp,method,params);
    if ( cp != 0 && method[0] != 0 && sender[0] != 0 && valid > 0 )
        retstr = bitcoind_RPC(0,cp->name,cp->serverport,cp->userpass,method,params);
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

char *python_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    char fname[MAX_JSON_FIELD],*retstr;
    int32_t launchflag,isws;
    if ( is_remote_access(previpaddr) != 0 )
        return(0);
    copy_cJSON(fname,objs[0]);
    launchflag = get_API_int(objs[1],0);
    isws = get_API_int(objs[2],0);
    if ( file_exists(fname) != 0 )
    {
        retstr = language_func(isws,launchflag,"python",fname,call_python);
        if ( retstr != 0 )
            printf("(%s) -> (%s)\n",fname,retstr);
        return(retstr);
    }
    else return(clonestr("{\"error\":\"file doesn't exist\"}"));
}

char *syscall_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    char arg[MAX_JSON_FIELD],syscall[MAX_JSON_FIELD];
    int32_t launchflag,isws;
    if ( is_remote_access(previpaddr) != 0 )
        return(0);
    copy_cJSON(syscall,objs[0]);
    launchflag = get_API_int(objs[1],0);
    isws = get_API_int(objs[2],0);
    copy_cJSON(arg,objs[3]);
    printf("isws.%d launchflag.%d syscall.(%s) arg.(%s)\n",isws,launchflag,syscall,arg);
    return(language_func(isws,launchflag,syscall,arg,call_system));
}

#endif
