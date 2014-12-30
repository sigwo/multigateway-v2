//
//  main.c
//  libtest
//
//  Created by jl777 on 8/13/14.
//  Copyright (c) 2014 jl777. MIT License.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <memory.h>
#include <arpa/inet.h>
#include <sys/time.h>

//Miniupnp code for supernet by chanc3r
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#define snprintf _snprintf
#else
// for IPPROTO_TCP / IPPROTO_UDP
#include <netinet/in.h>
#endif
#include "miniupnpc/miniwget.h"
#include "miniupnpc/miniupnpc.h"
#include "miniupnpc/upnpcommands.h"
#include "miniupnpc/upnperrors.h"


#include "SuperNET.h"
#include "cJSON.h"
#define NUM_GATEWAYS 3
extern char Server_names[256][MAX_JSON_FIELD],MGWROOT[];
extern char Server_NXTaddrs[256][MAX_JSON_FIELD];
extern int32_t IS_LIBTEST,USESSL,SUPERNET_PORT,ENABLE_GUIPOLL,Debuglevel,UPNP,MULTIPORT,Finished_init;
extern cJSON *MGWconf;
#define issue_curl(curl_handle,cmdstr) bitcoind_RPC(curl_handle,"curl",cmdstr,0,0,0)
char *bitcoind_RPC(void *deprecated,char *debugstr,char *url,char *userpass,char *command,char *params);
void expand_ipbits(char *ipaddr,uint32_t ipbits);
uint64_t conv_acctstr(char *acctstr);
void calc_sha256(char hashstr[(256 >> 3) * 2 + 1],unsigned char hash[256 >> 3],unsigned char *src,int32_t len);
int32_t decode_hex(unsigned char *bytes,int32_t n,char *hex);
int32_t expand_nxt64bits(char *NXTaddr,uint64_t nxt64bits);
char *clonestr(char *);

char *SuperNET_url()
{
    static char urls[2][64];
    sprintf(urls[0],"http://127.0.0.1:%d",SUPERNET_PORT+1);
    sprintf(urls[1],"https://127.0.0.1:%d",SUPERNET_PORT);
    return(urls[USESSL]);
}

cJSON *SuperAPI(char *cmd,char *field0,char *arg0,char *field1,char *arg1)
{
    cJSON *json;
    char params[1024],*retstr;
    if ( field0 != 0 && field0[0] != 0 )
    {
        if ( field1 != 0 && field1[0] != 0 )
            sprintf(params,"{\"requestType\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\"}",cmd,field0,arg0,field1,arg1);
        else sprintf(params,"{\"requestType\":\"%s\",\"%s\":\"%s\"}",cmd,field0,arg0);
    }
    else sprintf(params,"{\"requestType\":\"%s\"}",cmd);
    retstr = bitcoind_RPC(0,(char *)"BTCD",SuperNET_url(),(char *)"",(char *)"SuperNET",params);
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    return(json);
}

char *GUIpoll(char *txidstr,char *senderipaddr,uint16_t *portp)
{
    void unstringify(char *);
    char params[4096],buf[1024],buf2[1024],ipaddr[64],args[8192],*retstr;
    int32_t port;
    cJSON *json,*argjson;
    txidstr[0] = 0;
    sprintf(params,"{\"requestType\":\"GUIpoll\"}");
    retstr = bitcoind_RPC(0,(char *)"BTCD",SuperNET_url(),(char *)"",(char *)"SuperNET",params);
    //fprintf(stderr,"<<<<<<<<<<< SuperNET poll_for_broadcasts: issued bitcoind_RPC params.(%s) -> retstr.(%s)\n",params,retstr);
    if ( retstr != 0 )
    {
        //sprintf(retbuf+sizeof(ptrs),"{\"result\":%s,\"from\":\"%s\",\"port\":%d,\"args\":%s}",str,ipaddr,port,args);
        if ( (json= cJSON_Parse(retstr)) != 0 )
        {
            copy_cJSON(buf,cJSON_GetObjectItem(json,"result"));
            if ( buf[0] != 0 )
            {
                unstringify(buf);
                copy_cJSON(txidstr,cJSON_GetObjectItem(json,"txid"));
                if ( txidstr[0] != 0 )
                {
                    if ( Debuglevel > 0 )
                        fprintf(stderr,"<<<<<<<<<<< GUIpoll: (%s) for [%s]\n",buf,txidstr);
                }
                else
                {
                    copy_cJSON(ipaddr,cJSON_GetObjectItem(json,"from"));
                    copy_cJSON(args,cJSON_GetObjectItem(json,"args"));
                    port = (int32_t)get_API_int(cJSON_GetObjectItem(json,"port"),0);
                    if ( args[0] != 0 )
                    {
                        unstringify(args);
                        if ( Debuglevel > 2 )
                            printf("(%s) from (%s:%d) -> (%s) Qtxid.(%s)\n",args,ipaddr,port,buf,txidstr);
                        free(retstr);
                        retstr = clonestr(args);
                        if ( (argjson= cJSON_Parse(retstr)) != 0 )
                        {
                            copy_cJSON(buf2,cJSON_GetObjectItem(argjson,"result"));
                            if ( strcmp(buf2,"nothing pending") == 0 )
                                free(retstr), retstr = 0;
                            //else printf("RESULT.(%s)\n",buf2);
                            free_json(argjson);
                        }
                    }
                }
            }
            free_json(json);
        } else fprintf(stderr,"<<<<<<<<<<< GUI poll_for_broadcasts: PARSE_ERROR.(%s)\n",retstr);
        // free(retstr);
    } //else fprintf(stderr,"<<<<<<<<<<< BTCD poll_for_broadcasts: bitcoind_RPC returns null\n");
    return(retstr);
}

char *process_commandline_json(cJSON *json)
{
    char *inject_pushtx(char *coinstr,cJSON *json);
    int32_t init_hexbytes_noT(char *hexbytes,unsigned char *message,long len);
    bits256 issue_getpubkey(int32_t *haspubkeyp,char *acct);
    char *issue_MGWstatus(int32_t mask,char *coinstr,char *userNXTaddr,char *userpubkey,char *email,int32_t rescan,int32_t actionflag);
    struct multisig_addr *decode_msigjson(char *NXTaddr,cJSON *obj,char *sender);
    int32_t send_email(char *email,char *destNXTaddr,char *pubkeystr,char *msg);
    void issue_genmultisig(char *coinstr,char *userNXTaddr,char *userpubkey,char *email,int32_t buyNXT);
    char txidstr[1024],senderipaddr[1024],cmd[2048],coin[2048],userpubkey[2048],NXTacct[2048],userNXTaddr[2048],email[2048],convertNXT[2048],retbuf[1024],buf2[1024],coinstr[1024],cmdstr[512],*retstr = 0,*waitfor = 0,errstr[2048],*str;
    bits256 pubkeybits;
    unsigned char hash[256>>3],mypublic[256>>3];
    uint16_t port;
    uint64_t nxt64bits,checkbits,deposit_pending = 0;
    int32_t i,n,haspubkey,iter,gatewayid,actionflag = 0,rescan = 1;
    uint32_t buyNXT = 0;
    cJSON *array,*argjson,*retjson,*retjsons[3];
    copy_cJSON(cmdstr,cJSON_GetObjectItem(json,"webcmd"));
    if ( strcmp(cmdstr,"SuperNET") == 0 )
    {
        str = cJSON_Print(json);
        //printf("GOT webcmd.(%s)\n",str);
        retstr = bitcoind_RPC(0,"webcmd",SuperNET_url(),(char *)"",(char *)"SuperNET",str);
        free(str);
        return(retstr);
    }
    copy_cJSON(coin,cJSON_GetObjectItem(json,"coin"));
    copy_cJSON(cmd,cJSON_GetObjectItem(json,"requestType"));
    if ( strcmp(cmd,"pushtx") == 0 )
        return(inject_pushtx(coin,json));
    copy_cJSON(email,cJSON_GetObjectItem(json,"email"));
    copy_cJSON(NXTacct,cJSON_GetObjectItem(json,"NXT"));
    copy_cJSON(userpubkey,cJSON_GetObjectItem(json,"pubkey"));
    if ( userpubkey[0] == 0 )
    {
        pubkeybits = issue_getpubkey(&haspubkey,NXTacct);
        if ( haspubkey != 0 )
            init_hexbytes_noT(userpubkey,pubkeybits.bytes,sizeof(pubkeybits.bytes));
    }
    copy_cJSON(convertNXT,cJSON_GetObjectItem(json,"convertNXT"));
    if ( convertNXT[0] != 0 )
        buyNXT = (uint32_t)atol(convertNXT);
    nxt64bits = conv_acctstr(NXTacct);
    expand_nxt64bits(userNXTaddr,nxt64bits);
    decode_hex(mypublic,sizeof(mypublic),userpubkey);
    calc_sha256(0,hash,mypublic,32);
    memcpy(&checkbits,hash,sizeof(checkbits));
    if ( checkbits != nxt64bits )
    {
        sprintf(retbuf,"{\"error\":\"invalid pubkey\",\"pubkey\":\"%s\",\"NXT\":\"%s\",\"checkNXT\":\"%llu\"}",userpubkey,userNXTaddr,(long long)checkbits);
        return(clonestr(retbuf));
    }
    memset(retjsons,0,sizeof(retjsons));
    cmdstr[0] = 0;
    //printf("got cmd.(%s)\n",cmd);
    if ( strcmp(cmd,"newbie") == 0 )
    {
        waitfor = "MGWaddr";
        sprintf(cmdstr,"http://%s/MGW/msig/%s",Server_names[i],userNXTaddr);
        array = cJSON_GetObjectItem(MGWconf,"active");
        if ( array != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<100; i++) // flush queue
                GUIpoll(txidstr,senderipaddr,&port);
            for (iter=0; iter<3; iter++) // give chance for servers to consensus
            {
                for (i=0; i<n; i++)
                {
                    copy_cJSON(coinstr,cJSON_GetArrayItem(array,i));
                    if ( coinstr[0] != 0 )
                    {
                        issue_genmultisig(coinstr,userNXTaddr,userpubkey,email,buyNXT);
                        sleep(1);
                    }
                }
                sleep(1);
            }
        }
    }
    else if ( strcmp(cmd,"status") == 0 )
    {
        waitfor = "MGWresponse";
        sprintf(cmdstr,"http://%s/MGW/status/%s",Server_names[i],userNXTaddr);
        //printf("cmdstr.(%s) waitfor.(%s)\n",cmdstr,waitfor);
        retstr = issue_MGWstatus((1<<NUM_GATEWAYS)-1,coin,userNXTaddr,userpubkey,0,rescan,actionflag);
        if ( retstr != 0 )
            free(retstr), retstr = 0;
    }
    else return(clonestr("{\"error\":\"only newbie command is supported now\"}"));
    if ( waitfor != 0 )
    {
        for (i=0; i<3000; i++)
        {
            if ( (retstr= GUIpoll(txidstr,senderipaddr,&port)) != 0 )
            {
                if ( retstr[0] == '[' || retstr[0] == '{' )
                {
                    if ( (retjson= cJSON_Parse(retstr)) != 0 )
                    {
                        if ( is_cJSON_Array(retjson) != 0 && (n= cJSON_GetArraySize(retjson)) == 2 )
                        {
                            argjson = cJSON_GetArrayItem(retjson,0);
                            copy_cJSON(buf2,cJSON_GetObjectItem(argjson,"requestType"));
                            gatewayid = (int32_t)get_API_int(cJSON_GetObjectItem(argjson,"gatewayid"),-1);
                            if ( gatewayid >= 0 && gatewayid < 3 && retjsons[gatewayid] == 0 )
                            {
                                copy_cJSON(errstr,cJSON_GetObjectItem(argjson,"error"));
                                if ( strlen(errstr) > 0 || strcmp(buf2,waitfor) == 0 )
                                {
                                    retjsons[gatewayid] = retjson, retjson = 0;
                                    if ( retjsons[0] != 0 && retjsons[1] != 0 && retjsons[2] != 0 )
                                        break;
                                }
                            }
                        }
                        if ( retjson != 0 )
                            free_json(retjson);
                    }
                }
                //fprintf(stderr,"(%p) %s\n",retjson,retstr);
                free(retstr),retstr = 0;
            } else usleep(3000);
        }
    }
    for (i=0; i<3; i++)
        if ( retjsons[i] == 0 )
            break;
    if ( i < 3 && cmdstr[0] != 0 )
    {
        for (i=0; i<3; i++)
        {
            if ( retjsons[i] == 0 && (retstr= issue_curl(0,cmdstr)) != 0 )
            {
                /*printf("(%s) -> (%s)\n",cmdstr,retstr);
                 if ( (msigjson= cJSON_Parse(retstr)) != 0 )
                 {
                 if ( is_cJSON_Array(msigjson) != 0 && (n= cJSON_GetArraySize(msigjson)) > 0 )
                 {
                 for (j=0; j<n; j++)
                 {
                 item = cJSON_GetArrayItem(msigjson,j);
                 copy_cJSON(coinstr,cJSON_GetObjectItem(item,"coin"));
                 if ( strcmp(coinstr,xxx) == 0 )
                 {
                 msig = decode_msigjson(0,item,Server_NXTaddrs[i]);
                 break;
                 }
                 }
                 }
                 else msig = decode_msigjson(0,msigjson,Server_NXTaddrs[i]);
                 if ( msig != 0 )
                 {
                 free(msig);
                 free_json(msigjson);
                 if ( email[0] != 0 )
                 send_email(email,userNXTaddr,0,retstr);
                 //printf("[%s]\n",retstr);
                 return(retstr);
                 }
                 } else printf("error parsing.(%s)\n",retstr);
                 free_json(msigjson);
                 free(retstr);*/
                if ( retstr[0] == '{' || retstr[0] == '[' )
                {
                    //if ( email[0] != 0 )
                    //    send_email(email,userNXTaddr,0,retstr);
                    //return(retstr);
                    retjsons[i] = cJSON_Parse(retstr);
                }
                free(retstr);
            } //else printf("cant find (%s)\n",cmdstr);
        }
    }
    json = cJSON_CreateArray();
    for (i=0; i<3; i++)
    {
        char *load_filestr(char *userNXTaddr,int32_t gatewayid);
        char *filestr;
        if ( retjsons[i] == 0 && userNXTaddr[0] != 0 && (filestr= load_filestr(userNXTaddr,i)) != 0 )
        {
            retjsons[i] = cJSON_Parse(filestr);
            printf(">>>>>>>>>>>>>>> load_filestr!!! %s.%d json.%p\n",userNXTaddr,i,json);
        }
        if ( retjsons[i] != 0 )
            cJSON_AddItemToArray(json,retjsons[i]);
    }
    if ( deposit_pending != 0 )
    {
        actionflag = 1;
        rescan = 0;
        retstr = issue_MGWstatus(1<<NUM_GATEWAYS,coin,0,0,0,rescan,actionflag);
        if ( retstr != 0 )
            free(retstr), retstr = 0;
    }
    retstr = cJSON_Print(json);
    free_json(json);
    if ( email[0] != 0 )
        send_email(email,userNXTaddr,0,retstr);
    for (i=0; i<1000; i++)
    {
        if ( (str= GUIpoll(txidstr,senderipaddr,&port)) != 0 )
            free(str);
        else break;
    }
    return(retstr);
}

char *load_filestr(char *userNXTaddr,int32_t gatewayid)
{
    long fpos;
    FILE *fp;
    char fname[1024],*buf,*retstr = 0;
    sprintf(fname,"%s/gateway%d/%s",MGWROOT,gatewayid,userNXTaddr);
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        fpos = ftell(fp);
        if ( fpos > 0 )
        {
            rewind(fp);
            buf = calloc(1,fpos);
            if ( fread(buf,1,fpos,fp) == fpos )
                retstr = buf, buf = 0;
        }
        fclose(fp);
        if ( buf != 0 )
            free(buf);
    }
    return(retstr);
}

void bridge_handler(struct transfer_args *args)
{
    FILE *fp;
    int32_t gatewayid;
    char fname[1024],cmd[1024],*name = args->name;
    if ( strncmp(name,"MGW",3) == 0 && name[3] >= '0' && name[3] <= '2' )
    {
        gatewayid = (name[3] - '0');
        name += 5;
        sprintf(fname,"%s/gateway%d/%s",MGWROOT,gatewayid,name);
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            fwrite(args->data,1,args->totallen,fp);
            fclose(fp);
            sprintf(cmd,"chmod +r %s",fname);
            system(cmd);
        }
    }
    printf("bridge_handler.gateway%d/(%s).%d\n",gatewayid,name,args->totallen);
}

void *GUIpoll_loop(void *arg)
{
    uint16_t port;
    char txidstr[1024],senderipaddr[1024],*retstr;
    while ( 1 )
    {
        sleep(1);
        if ( (retstr= GUIpoll(txidstr,senderipaddr,&port)) != 0 )
            free(retstr);
    }
    return(0);
}


// redirect port on external upnp enabled router to port on *this* host
int upnpredirect(const char* eport, const char* iport, const char* proto, const char* description) {
    
    //  Discovery parameters
    struct UPNPDev * devlist = 0;
    struct UPNPUrls urls;
    struct IGDdatas data;
    int i;
    char lanaddr[64];	// my ip address on the LAN
    const char* leaseDuration="0";
    
    //  Redirect & test parameters
    char intClient[40];
    char intPort[6];
    char externalIPAddress[40];
    char duration[16];
    int error=0;
    
    //  Find UPNP devices on the network
    if ((devlist=upnpDiscover(2000, 0, 0,0, 0, &error))) {
        struct UPNPDev * device = 0;
        printf("UPNP INIALISED: List of UPNP devices found on the network.\n");
        for(device = devlist; device; device = device->pNext) {
            printf("UPNP INFO: dev [%s] \n\t st [%s]\n",
                   device->descURL, device->st);
        }
    } else {
        printf("UPNP ERROR: no device found - MANUAL PORTMAP REQUIRED\n");
        return 0;
    }
    
    //  Output whether we found a good one or not.
    if((error = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr)))) {
        switch(error) {
            case 1:
                printf("UPNP OK: Found valid IGD : %s\n", urls.controlURL);
                break;
            case 2:
                printf("UPNP WARN: Found a (not connected?) IGD : %s\n", urls.controlURL);
                break;
            case 3:
                printf("UPNP WARN: UPnP device found. Is it an IGD ? : %s\n", urls.controlURL);
                break;
            default:
                printf("UPNP WARN: Found device (igd ?) : %s\n", urls.controlURL);
        }
        printf("UPNP OK: Local LAN ip address : %s\n", lanaddr);
    } else {
        printf("UPNP ERROR: no device found - MANUAL PORTMAP REQUIRED\n");
        return 0;
    }
    
    //  Get the external IP address (just because we can really...)
    if(UPNP_GetExternalIPAddress(urls.controlURL,
                                 data.first.servicetype,
                                 externalIPAddress)!=UPNPCOMMAND_SUCCESS)
        printf("UPNP WARN: GetExternalIPAddress failed.\n");
    else
        printf("UPNP OK: ExternalIPAddress = %s\n", externalIPAddress);
    
    //  Check for existing supernet mapping - from this host and another host
    //  In theory I can adapt this so multiple nodes can exist on same lan and choose a different portmap
    //  for each one :)
    //  At the moment just delete a conflicting portmap and override with the one requested.
    i=0;
    error=0;
    do {
        char index[6];
        char extPort[6];
        char desc[80];
        char enabled[6];
        char rHost[64];
        char protocol[4];
        
        snprintf(index, 6, "%d", i++);
        
        if(!(error=UPNP_GetGenericPortMappingEntry(urls.controlURL,
                                                   data.first.servicetype,
                                                   index,
                                                   extPort, intClient, intPort,
                                                   protocol, desc, enabled,
                                                   rHost, duration))) {
            // printf("%2d %s %5s->%s:%-5s '%s' '%s' %s\n",i, protocol, extPort, intClient, intPort,desc, rHost, duration);
            
            // check for an existing supernet mapping on this host
            if(!strcmp(lanaddr, intClient)) { // same host
                if(!strcmp(protocol,proto)) { //same protocol
                    if(!strcmp(intPort,iport)) { // same port
                        printf("UPNP WARN: existing mapping found (%s:%s)\n",lanaddr,iport);
                        if(!strcmp(extPort,eport)) {
                            printf("UPNP OK: exact mapping already in place (%s:%s->%s)\n", lanaddr, iport, eport);
                            FreeUPNPUrls(&urls);
                            freeUPNPDevlist(devlist);
                            return 1;
                            
                        } else { // delete old mapping
                            printf("UPNP WARN: deleting existing mapping (%s:%s->%s)\n",lanaddr, iport, extPort);
                            if(UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, extPort, proto, rHost))
                                printf("UPNP WARN: error deleting old mapping (%s:%s->%s) continuing\n", lanaddr, iport, extPort);
                            else printf("UPNP OK: old mapping deleted (%s:%s->%s)\n",lanaddr, iport, extPort);
                        }
                    }
                }
            } else { // ipaddr different - check to see if requested port is already mapped
                if(!strcmp(protocol,proto)) {
                    if(!strcmp(extPort,eport)) {
                        printf("UPNP WARN: EXT port conflict mapped to another ip (%s-> %s vs %s)\n", extPort, lanaddr, intClient);
                        if(UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, extPort, proto, rHost))
                            printf("UPNP WARN: error deleting conflict mapping (%s:%s) continuing\n", intClient, extPort);
                        else printf("UPNP OK: conflict mapping deleted (%s:%s)\n",intClient, extPort);
                    }
                }
            }
        } else
            printf("UPNP OK: GetGenericPortMappingEntry() End-of-List (%d entries) \n", i);
    } while(error==0);
    
    //  Set the requested port mapping
    if((i=UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                              eport, iport, lanaddr, description,
                              proto, 0, leaseDuration))!=UPNPCOMMAND_SUCCESS) {
        printf("UPNP ERROR: AddPortMapping(%s, %s, %s) failed with code %d (%s)\n",
               eport, iport, lanaddr, i, strupnperror(i));
        
        FreeUPNPUrls(&urls);
        freeUPNPDevlist(devlist);
        return 0; //error - adding the port map primary failure
    }
    
    if((i=UPNP_GetSpecificPortMappingEntry(urls.controlURL,
                                           data.first.servicetype,
                                           eport, proto, NULL/*remoteHost*/,
                                           intClient, intPort, NULL/*desc*/,
                                           NULL/*enabled*/, duration))!=UPNPCOMMAND_SUCCESS) {
        printf("UPNP ERROR: GetSpecificPortMappingEntry(%s, %s, %s) failed with code %d (%s)\n", eport, iport, lanaddr,
               i, strupnperror(i));
        FreeUPNPUrls(&urls);
        freeUPNPDevlist(devlist);
        return 0; //error - port map wasnt returned by query so likely failed.
    }
    else printf("UPNP OK: EXT (%s:%s) %s redirected to INT (%s:%s) (duration=%s)\n",externalIPAddress, eport, proto, intClient, intPort, duration);
    FreeUPNPUrls(&urls);
    freeUPNPDevlist(devlist);
    return 1; //ok - we are mapped:)
}



struct coinscripts
{
    char prefix[16],suffix[16];
};

struct coinaddr
{
    uint8_t addr[35],pubkey[66];
    uint32_t numentries,allocsize,ind;
    struct address_entry entries[];
};

struct scriptinfo
{
    uint32_t ind,mode;
    uint8_t script[];
};

struct txout
{
    uint32_t scriptind:2,addrind:30;
    uint64_t value;
};

struct txinfo
{
    uint8_t txidstr[128];
    uint16_t numvouts,numvins;
    uint32_t ind;
    uint32_t txouts[]; // both vouts and vins in same array, vouts first
};

struct blockinfo
{
    uint16_t numtx;
    uint8_t txs[];
};

void update_block(struct blockinfo *block,struct address_entry *entry)
{
    if ( entry->txind > block->numtx )
        block->numtx = entry->txind;
}

/*
void cross_validate_rawfiles(char *coin,char *addr,struct address_entry *bp)
{
    static uint32_t n,maxblock;
    uint32_t ind,numinds,size;
    struct huffcode *huff;
    struct coin_info *cp;
    cp = get_coin_info(coin);
    numinds = 1000000;
    if ( cp->items == 0 )
    {
        cp->items = calloc(numinds,sizeof(*cp->items));
    }
    if ( addr == 0  || (n % 100) == 99 )
    {
        if ( cp != 0 )
        {
            double endmilli,startmilli = milliseconds();
            size = 1;
            for (ind=1; ind<numinds; ind++)
            {
                if ( ind == (1 << 8) )
                    size = 2;
                else if ( ind == (1 << 16) )
                    size = 3;
                else if ( ind == (1 << 24) )
                    size = 4;
                huff_iteminit(&cp->items[ind],&ind,size,0,0);
            }
            printf("items initialized\n");
            testhuffcode("hello",cp->items,numinds);
            huff = huff_init(cp->items,numinds);
            endmilli = milliseconds();
            printf("%.3f millis to encode maxblock.%d BTCD.%d %d bytes -> %d bits %.3f ratio\n",endmilli-startmilli,maxblock,n,huff->totalbytes,huff->totalbits,(double)huff->totalbytes*8./huff->totalbits);
        }
        return;
    }
    n++;
    if ( bp->blocknum > maxblock )
        maxblock = bp->blocknum;
    cp->items[bp->blocknum].freq++;
    cp->items[bp->txind].freq++;
    cp->items[bp->v].freq++;
    //update_block(&cp->blocks[bp->blocknum],bp);
    //struct address_entry { uint64_t blocknum:32,txind:15,vinflag:1,v:14,spent:1,isinternal:1; };
    printf("%d: max.%d %7u %-5u %-5u (%-5s %s) vin.%d spent.%d isinternal.%d\n",n,maxblock,bp->blocknum,bp->txind,bp->v,coin,addr,bp->vinflag,bp->spent,bp->isinternal);
}*/

int32_t _calc_bitsize(uint32_t x)
{
    uint32_t mask = (1 << 31);
    int32_t i;
    if ( x == 0 )
        return(0);
    for (i=31; i>=0; i--)
    {
        if ( (mask & x) != 0 )
            return(i);
    }
    return(-1);
}

int32_t emit_varbits(HUFF *hp,uint8_t val)
{
    int i,valsize = _calc_bitsize(val);
    for (i=0; i<3; i++)
        hputbit(hp,(valsize & (1<<i)) != 0);
    for (i=0; i<valsize; i++)
        hputbit(hp,(val & (1<<i)) != 0);
    return(valsize + 3);
}

int32_t emit_valuebits(HUFF *hp,uint8_t value)
{
    int32_t i,num,valsize,lsb = 0;
    uint64_t mask;
    mask = (1L << 63);
    for (i=63; i>=0; i--,mask>>=1)
        if ( (value & mask) != 0 )
            break;
    mask = 1;
    for (lsb=0; lsb<i; lsb++,mask<<=1)
        if ( (value & mask) != 0 )
            break;
    value >>= lsb;
    valsize = (i - lsb);
    num = emit_varbits(hp,lsb);
    num += emit_varbits(hp,valsize);
    mask = 1;
    for (i=0; i<valsize; i++,mask<<=1)
        hputbit(hp,(value & mask) != 0);
    printf("%d ",num+valsize);
    return(num + valsize);
}

int32_t choose_varbits(HUFF *hp,uint32_t val,int32_t diff)
{
    int valsize,diffsize,i,num = 0;
    valsize = _calc_bitsize(val);
    diffsize = _calc_bitsize(diff < 0 ? -diff : diff);
    if ( valsize < diffsize )
    {
        hputbit(hp,0);
        hputbit(hp,1);
        num = 2 + valsize + emit_varbits(hp,valsize);
        for (i=0; i<valsize; i++)
            hputbit(hp,(val & (1<<i)) != 0);
    }
    else
    {
        num = 1;
        if ( diff < 0 )
        {
            hputbit(hp,0);
            hputbit(hp,0);
            num++;
        }
        else hputbit(hp,1);
        num += emit_varbits(hp,diffsize) + diffsize;
        for (i=0; i<diffsize; i++)
            hputbit(hp,(diff & (1<<i)) != 0);
    }
    return(num);
}

void update_ramchain(struct compressionvars *V,char *coinstr,char *addr,struct address_entry *bp,uint64_t value,char *txidstr,char *script)
{
    struct hashtable *hashtable_create(char *name,int64_t hashsize,long structsize,long keyoffset,long keysize,long modifiedoffset);
    void *add_hashtable(int32_t *createdflagp,struct hashtable **hp_ptr,char *key);
    uint32_t len;
    uint16_t slen;
    char fname[512];
    char mode;
    int32_t createdflag,flag,valA,valT,valS;
    struct coinaddr *addrp = 0;
    struct txinfo *tp = 0;
    struct scriptinfo *sp = 0;
    if ( V->fp == 0 )
    {
        if ( IS_LIBTEST != 7 )
        {
            sprintf(fname,"address/%s/%s",coinstr,addr);
            if ( (V->fp= fopen(fname,"rb+")) == 0 )
                V->fp = fopen(fname,"wb");
            else fseek(V->fp,0,SEEK_END);
        }
        else
        {
            V->buffer = calloc(1,1000000);
            V->hp = hopen(V->buffer,1000000);
            V->addrs = hashtable_create("addrs",100,sizeof(*addrp),((long)&addrp->addr[0] - (long)addrp),sizeof(addrp->addr),-1);
            V->txids = hashtable_create("txids",100,sizeof(*tp),((long)&tp->txidstr[0] - (long)tp),sizeof(tp->txidstr),-1);
            V->scripts = hashtable_create("scripts",100,sizeof(*sp),sizeof(*sp),0,-1);
            sprintf(fname,"address/%s.raw",coinstr);
            V->fp = fopen(fname,"wb");
            printf("opened %s\n",fname);
            sprintf(fname,"address/%s.addrs",coinstr);
            V->afp = fopen(fname,"wb");
            printf("opened %s\n",fname);
            sprintf(fname,"address/%s.txids",coinstr);
            V->tfp = fopen(fname,"wb");
            printf("opened %s\n",fname);
            sprintf(fname,"address/%s.scripts",coinstr);
            V->sfp = fopen(fname,"wb");
            printf("opened %s\n",fname);
            V->prevblock = V->prevaddrind = V->prevtxind = V->prevscriptind = -1;
        }
    }
    if ( V->fp != 0 )
    {
        if ( bp->vinflag == 0 && script != 0 && txidstr != 0 )
        {
            if ( V->prevblock != bp->blocknum )
            {
                emit_varbits(V->hp,V->numentries);
                hflush(V->fp,V->hp);
                hclear(V->hp);
                printf("-> numentries.%d %.1f %.1f\n\nNEWBLOCK.%u A%u T%u S%u\n",V->numentries,(double)(ftell(V->fp)+ftell(V->afp)+ftell(V->tfp)+ftell(V->sfp))/bp->blocknum,(double)ftell(V->fp)/bp->blocknum,bp->blocknum,V->prevaddrind,V->prevtxind,V->prevscriptind);
                V->numentries = 0;
            }
            V->numentries++;
            emit_valuebits(V->hp,value);
            //fwrite(&value,1,sizeof(value),fp);
            if ( txidstr != 0 && script != 0 )
            {
                len = (int32_t)strlen(script);
                if ( strncmp(script,"76a914",6) == 0 && strcmp(script+len-4,"88ac") == 0 )
                {
                    script[len-4] = 0;
                    script += 6;
                    mode = 's';
                }
                else if ( strncmp(script,"a9",2) == 0 && strcmp(script+len-2,"ac") == 0 )
                {
                    script[len-2] = 0;
                    script += 2;
                    mode = 'm';
                }
                else mode = 'r';
                flag = 0;
                addrp = add_hashtable(&createdflag,&V->addrs,addr);
                if ( createdflag != 0 )
                {
                    addrp->ind = ++V->addrind;
                    //printf("%s ",addr);
                    slen = (int32_t)strlen(addr) + 1;
                    fwrite(&slen,1,sizeof(slen),V->afp);
                    fwrite(addr,1,slen,V->afp);
                    fflush(V->afp);
                    flag++;
                }
                valA = addrp->ind - V->prevaddrind;
                sprintf(addr,"a%d",valA);
                V->prevaddrind = addrp->ind;
                
                tp = add_hashtable(&createdflag,&V->txids,txidstr);
                if ( createdflag != 0 )
                {
                    tp->ind = ++V->txidind;
                    //printf("%s ",txidstr);
                    slen = (int32_t)strlen(txidstr) + 1;
                    fwrite(&slen,1,sizeof(slen),V->tfp);
                    fwrite(txidstr,1,slen,V->tfp);
                    fflush(V->tfp);
                    flag++;
                }
                valT = tp->ind - V->prevtxind;
                sprintf(txidstr,"t%d",valT);
                V->prevtxind = tp->ind;
                
                sp = add_hashtable(&createdflag,&V->scripts,script);
                if ( createdflag != 0 )
                {
                    sp->ind = ++V->scriptind;
                    sp->mode = mode;
                    //printf("%s ",script);
                    slen = (int32_t)strlen(script) + 1;
                    fwrite(&slen,1,sizeof(slen),V->sfp);
                    fwrite(script,1,slen,V->sfp);
                    fflush(V->sfp);
                    flag++;
                }
                valS = sp->ind - V->prevscriptind;
                sprintf(script,"s%d",valS);
                V->prevscriptind = sp->ind;
                
                //if ( flag != 0 )
                //    printf("\n");
                //printf("%s %6u.%-5u %s:%d %s %c%s %.8f | %.1f\n",coinstr,bp->blocknum,bp->txind,txidstr,bp->v,addr,mode,script,dstr(value),(double)(ftell(fp)+ftell(afp)+ftell(tfp)+ftell(sfp))/(bp->blocknum+1));
                //fwrite(&mode,1,sizeof(mode),fp);
                printf("{%d.%d %d.%d %d.%d %.8f} ",V->prevaddrind,valA,V->prevtxind,valT,V->prevscriptind,valS,dstr(value));
                choose_varbits(V->hp,V->prevaddrind,valA);
                choose_varbits(V->hp,V->prevtxind,valS);
                choose_varbits(V->hp,V->prevscriptind,valT);
            }
            else
            {
                printf("[%d %d %d] ",bp->blocknum,bp->txind,bp->v);
                //fwrite(bp,1,sizeof(*bp),fp);
            }
        }
        else
        {
            printf("(%d %d %d) ",bp->blocknum,bp->txind,bp->v);
            //fwrite(bp,1,sizeof(*bp),fp);
        }
        if ( IS_LIBTEST != 7 )
            fclose(V->fp);
        else fflush(V->fp);
    }
}

int main(int argc,const char *argv[])
{
    FILE *fp;
    cJSON *json = 0;
    int32_t retval;
    char ipaddr[64],*oldport,*newport,portstr[64],*retstr;
   // if ( Debuglevel > 0 )
    if ( IS_LIBTEST == 7 )
    {
        uint32_t process_coinblocks(char *coinstr,uint32_t blockheight,int32_t dispflag);
        uint32_t blockheight = 0;
        IS_LIBTEST = 7;
        retval = SuperNET_start("SuperNET.conf","127.0.0.1");
        process_coinblocks("BTCD",blockheight,0);
        getchar();
    }
    if ( 0 )
    {
        void huff_iteminit(struct huffitem *hip,void *ptr,int32_t size,int32_t isptr,int32_t ishex);
        char *p,*str = "this is an example for huffman encoding";
        int i,numinds = 256;
        struct huffitem *items = calloc(numinds,sizeof(*items));
        int testhuffcode(char *str,struct huffitem *freqs,int32_t numinds);
        for (i=0; i<numinds; i++)
            huff_iteminit(&items[i],&i,1,0,0);
        p = str;
        while ( *p != '\0' )
            items[*p++].freq++;
        testhuffcode(str,items,numinds);
        //getchar();
        system("git log | head -n 1");
    }
    IS_LIBTEST = 1;
    if ( argc > 1 && argv[1] != 0 )
    {
        char *init_MGWconf(char *JSON_or_fname,char *myipaddr);
        //printf("ARGV1.(%s)\n",argv[1]);
        if ( (argv[1][0] == '{' || argv[1][0] == '[') )
        {
            if ( (json= cJSON_Parse(argv[1])) != 0 )
            {
                Debuglevel = IS_LIBTEST = -1;
                init_MGWconf("SuperNET.conf",0);
                if ( (retstr= process_commandline_json(json)) != 0 )
                {
                    printf("%s\n",retstr);
                    free(retstr);
                }
                free_json(json);
                return(0);
            }
        }
        else strcpy(ipaddr,argv[1]);
    }
    else strcpy(ipaddr,"127.0.0.1");
    retval = SuperNET_start("SuperNET.conf",ipaddr);
    sprintf(portstr,"%d",SUPERNET_PORT);
    oldport = newport = portstr;
    if ( UPNP != 0 && upnpredirect(oldport,newport,"UDP","SuperNET_https") == 0 )
        printf("TEST ERROR: failed redirect (%s) to (%s)\n",oldport,newport);
    //sprintf(portstr,"%d",SUPERNET_PORT+1);
    //oldport = newport = portstr;
    //if ( upnpredirect(oldport,newport,"UDP","SuperNET_http") == 0 )
    //    printf("TEST ERROR: failed redirect (%s) to (%s)\n",oldport,newport);
    printf("saving retval.%x (%d usessl.%d) UPNP.%d MULTIPORT.%d\n",retval,retval>>1,retval&1,UPNP,MULTIPORT);
    if ( (fp= fopen("horrible.hack","wb")) != 0 )
    {
        fwrite(&retval,1,sizeof(retval),fp);
        fclose(fp);
    }
    if ( retval >= 0 && ENABLE_GUIPOLL != 0 )
    {
        GUIpoll_loop(ipaddr);
        //if ( portable_thread_create((void *)GUIpoll_loop,ipaddr) == 0 )
        //    printf("ERROR hist process_hashtablequeues\n");
    }
    while ( 1 )
        sleep(60);
    return(0);
}


// stubs
int32_t SuperNET_broadcast(char *msg,int32_t duration) { return(0); }
int32_t SuperNET_narrowcast(char *destip,unsigned char *msg,int32_t len) { return(0); }

#ifdef chanc3r
#endif
