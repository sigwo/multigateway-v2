//
//  console777.c
//  crypto777
//
//  Created by James on 4/9/15.
//  Copyright (c) 2015 jl777. All rights reserved.
//

#ifdef DEFINES_ONLY
#ifndef crypto777_console777_h
#define crypto777_console777_h
#include <stdio.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "cJSON.h"
#include "db777.c"
#include "system777.c"

#endif
#else
#ifndef crypto777_console777_c
#define crypto777_console777_c

#ifndef crypto777_console777_h
#define DEFINES_ONLY
#include "console777.c"
#undef DEFINES_ONLY
#endif

int32_t getline777(char *line,int32_t max)
{
    static char prevline[1024];
    struct timeval timeout;
    fd_set fdset;
    int32_t s;
    line[0] = 0;
    FD_ZERO(&fdset);
    FD_SET(STDIN_FILENO,&fdset);
    timeout.tv_sec = 0, timeout.tv_usec = 10000;
    if ( (s= select(1,&fdset,NULL,NULL,&timeout)) < 0 )
        fprintf(stderr,"wait_for_input: error select s.%d\n",s);
    else
    {
        if ( FD_ISSET(STDIN_FILENO,&fdset) > 0 && fgets(line,max,stdin) == line )
        {
            line[strlen(line)-1] = 0;
            if ( line[0] == 0 || (line[0] == '.' && line[1] == 0) )
                strcpy(line,prevline);
            else strcpy(prevline,line);
        }
    }
    return((int32_t)strlen(line));
}

int32_t settoken(char *token,char *line)
{
    int32_t i;
    for (i=0; i<32&&line[i]!=0; i++)
    {
        if ( line[i] == ' ' || line[i] == '\n' || line[i] == '\t' || line[i] == '\b' || line[i] == '\r' )
            break;
        token[i] = line[i];
    }
    if ( line[i] == 0 )
    {
        printf("invalid alias assignment\n");
        return(-1);
    }
    token[i] = 0;
    return(i);
}

void update_alias(char *line)
{
    char retbuf[8192],alias[1024],*value; int32_t i;
    if ( (i= settoken(&alias[1],line)) < 0 )
        return;
    alias[0] = '#';
    value = &line[i+1];
    if ( value[0] == 0 )
        printf("warning value for %s is null\n",alias);
    if ( db777_findstr(retbuf,sizeof(retbuf),DB_nodestats,alias) == 0 )
    {
        if ( strcmp(retbuf,value) == 0 )
            printf("UNCHANGED ");
        else printf("%s ",retbuf[0] == 0 ? "CREATE" : "UPDATE");
        printf(" (%s) -> (%s)\n",alias,value);
        if ( db777_addstr(DB_nodestats,alias,value) != 0 )
            printf("error updating alias database\n");
    } else printf("alias database error to add alias (%s -> %s)\n",alias,value);
}

void expand_aliases(char *expanded,int32_t max,char *line)
{
    char alias[64],value[8192];
    int32_t i,j,k,len,flag = 1;
    while ( len < max-8192 && flag != 0 )
    {
        flag = 0;
        len = (int32_t)strlen(line);
        for (i=j=0; i<len; i++)
        {
            if ( line[i] == '#' )
            {
                if ( (k= settoken(&alias[1],&line[i+1])) < 0 )
                    return;
                alias[0] = '#';
                if ( db777_findstr(value,sizeof(value),DB_nodestats,alias) == 0 && value[0] != 0 )
                    for (k=0; value[k]!=0; k++)
                        expanded[j++] = value[k];
                flag++;
            } else expanded[j++] = line[i];
        }
    }
}

char *localcommand(char *line)
{
    static char *expanded;
    char *retstr;
    if ( strcmp(line,"list") == 0 )
    {
        if ( (retstr= relays_jsonstr(0,0)) != 0 )
        {
            printf("%s\n",retstr);
            free(retstr);
        }
        return(0);
    }
    else if ( strncmp(line,"alias",5) == 0 )
    {
        update_alias(line+6);
        return(0);
    }
    else if ( strcmp(line,"help") == 0 )
    {
        printf("local commands:\nhelp, list, alias <name> <any string> then #name is expanded to <any string>\n");
        printf("<plugin name> <method> {json args} -> invokes plugin with method and args, \"myipaddr\" and \"NXT\" are default attached\n\n");
        printf("network commands: default timeout is used if not specified\n");
        printf("relay <plugin name> <method> {json args} -> will send to random relay\n");
        printf("peers <plugin name> <method> {json args} -> will send all peers\n");
        printf("!<plugin name> <method> {json args} -> sends to random relay which will send to all peers and collate results.\n\n");
        
        printf("publish shortcut: pub <any string> -> invokes the subscriptions plugin with publish method\n\n");
        
        printf("direct to specific relay need to have a direct connection established first:\nrelay direct or peers direct <ipaddr>\n");
        printf("in case you cant directly reach a specific relay with \"peers direct <ipaddr>\" you can add \"!\" and let a relay broadcast\n");
        printf("without an <ipaddr> it will connect to a random relay. Once directly connected, commands are sent by:\n");
        printf("<ipaddress> {\"plugin\":\"<name>\",\"method\":\"<methodname>\",...}\n");
        printf("responses to direct requests are sent through as a subscription feed\n\n");
        
        printf("\"relay join\" adds your node to the list of relay nodes, your node will need to stay in sync with the other relays\n");
        //printf("\"relay mailbox <64bit number> <name>\" creates synchronized storage in all relays\n");
        return(0);
    }
    if ( expanded == 0 )
        expanded = calloc(1,65536);
    expand_aliases(expanded,65536,line);
    return(expanded);
}

void process_userinput(char *_line)
{
    char plugin[512],method[512],*line,*str,*cmdstr,*retstr,*pubstr; cJSON *json; int i,j,timeout,broadcastflag = 0;
    printf("[%s]\n",_line);
    if ( (line= localcommand(_line)) == 0 )
        return;
    printf("expands to: %s\n",line);
    if ( line[0] == '!' )
        broadcastflag = 1, line++;
    for (i=0; i<512&&line[i]!=' '&&line[i]!=0; i++)
        plugin[i] = line[i];
    plugin[i] = 0;
    pubstr = line;
    if ( strcmp(plugin,"pub") == 0 )
        strcpy(plugin,"subscriptions"), strcpy(method,"publish"), pubstr += 4;
    else if ( line[i+1] != 0 )
    {
        for (++i,j=0; i<512&&line[i]!=' '&&line[i]!=0; i++,j++)
            method[j] = line[i];
        method[j] = 0;
    } else method[0] = 0;
    if ( (json= cJSON_Parse(line+i+1)) == 0 )
    {
        json = cJSON_CreateObject();
        if ( line[i+1] != 0 )
        {
            str = stringifyM(&line[i+1]);
            cJSON_AddItemToObject(json,"content",cJSON_CreateString(str));
        }
        free(str);
        if ( cJSON_GetObjectItem(json,"myipaddr") == 0 )
            cJSON_AddItemToObject(json,"myipaddr",cJSON_CreateString(SUPERNET.myipaddr));
        if ( cJSON_GetObjectItem(json,"NXT") == 0 )
            cJSON_AddItemToObject(json,"NXT",cJSON_CreateString(SUPERNET.NXTADDR));
    }
    if ( json != 0 )
    {
        struct daemon_info *find_daemoninfo(int32_t *indp,char *name,uint64_t daemonid,uint64_t instanceid);
        timeout = get_API_int(cJSON_GetObjectItem(json,"timeout"),0);
        if ( plugin[0] == 0 )
            strcpy(plugin,"relay");
        cJSON_AddItemToObject(json,"plugin",cJSON_CreateString(plugin));
        if ( method[0] == 0 )
            strcpy(method,"help");
        cJSON_AddItemToObject(json,"method",cJSON_CreateString(method));
        if ( broadcastflag != 0 )
            cJSON_AddItemToObject(json,"broadcast",cJSON_CreateString("allpeers"));
        cmdstr = cJSON_Print(json);
        _stripwhite(cmdstr,' ');
        if ( broadcastflag != 0 || strcmp(plugin,"relay") == 0 )
            retstr = nn_loadbalanced(cmdstr);
        else if ( strcmp(plugin,"peers") == 0 )
            retstr = nn_allpeers(cmdstr,timeout != 0 ? timeout : RELAYS.surveymillis,0);
        else if ( find_daemoninfo(&j,plugin,0,0) != 0 )
            retstr = plugin_method(0,1,plugin,method,0,0,cmdstr,timeout != 0 ? timeout : 0);
        else if ( is_ipaddr(plugin) != 0 )
            retstr = nn_direct(plugin,cmdstr);
        else retstr = nn_publish(pubstr,0);
        printf("(%s) -> (%s) -> (%s)\n",line,cmdstr,retstr);
        free(cmdstr);
        free_json(json);
    } else printf("cant create json object for (%s)\n",line);
}

#endif
#endif
