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
int32_t init_hexbytes_noT(char *hexbytes,unsigned char *message,long len);

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
        if ( (fp= fopen(fname,"wb+")) != 0 )
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

#define HUFF_VALUE 0
#define HUFF_COINADDR 1
#define HUFF_TXID 2
#define HUFF_SCRIPT 3
#define HUFF_BLOCKNUM 4
#define HUFF_TXIND 5
#define HUFF_VOUT 6
#define HUFF_RESERVED 7

int32_t clear_hashtable_field(struct hashtable *hp,long offset,long fieldsize);
int32_t gather_hashtable_field(void **items,int32_t numitems,int32_t maxitems,struct hashtable *hp,long offset,long fieldsize);
struct hashtable *hashtable_create(char *name,int64_t hashsize,long structsize,long keyoffset,long keysize,long modifiedoffset);
void *add_hashtable(int32_t *createdflagp,struct hashtable **hp_ptr,char *key);
void **hashtable_gather_modified(int64_t *changedp,struct hashtable *hp,int32_t forceflag);
struct huffcode *huff_create(const struct huffitem **items,int32_t numinds,int32_t frequi);
void huff_iteminit(struct huffitem *hip,uint32_t huffind,void *ptr,long size,long wt);
void huff_free(struct huffcode *huff);
void huff_clearstats(struct huffcode *huff);
char *_mbstr(double n);
int32_t save_vfilestr(FILE *fp,char *str);
int32_t load_vfilestr(int32_t *lenp,char *str,FILE *fp);
long emit_varint(FILE *fp,uint64_t x);
double milliseconds();
struct coin_info *get_coin_info(char *coinstr);
uint32_t get_blockheight(struct coin_info *cp);

uint32_t BITSTREAM_GROUPSIZE(char *coinstr)
{
    if ( strcmp(coinstr,"BTC") == 0 )
        return(1000);
    else return(10000);
}

int32_t calc_frequi(uint32_t *slicep,char *coinstr,uint32_t blocknum)
{
    int32_t slice,incr;
    incr = 1000;//BITSTREAM_GROUPSIZE(coinstr);
    slice = (incr / HUFF_NUMFREQS);
    if ( slicep != 0 )
        *slicep = slice;
    return((blocknum / slice) % HUFF_NUMFREQS);
}

struct coinaddr
{
    uint32_t ind,numentries,allocsize,pad;
    struct huffitem item;
    uint8_t binaryaddr[24];
    struct address_entry *entries;
    char addr[];
};

struct valueinfo
{
    uint32_t ind,pad;
    uint64_t value;
    struct huffitem item;
    char valuestr[];
};

struct scriptinfo
{
    uint32_t ind,addrind;
    struct huffitem item;
    char mode,scriptstr[];
};

struct txinfo
{
    uint32_t ind,allocsize,numentries;
    uint16_t numvouts,numvins;
    struct huffitem item;
    struct address_entry *entries;
    char txidstr[];
};

void clear_compressionvars(struct compressionvars *V,int32_t clearstats,int32_t frequi)
{
    int32_t i;
    struct scriptinfo *sp = 0;
    struct txinfo *tp = 0;
    struct coinaddr *addrp = 0;
    struct valueinfo *valp = 0;
    V->maxitems = 0;
    memset(V->rawdata,0,sizeof(*V->rawdata));
    if ( clearstats != 0 )
    {
        clear_hashtable_field(V->values,(long)((long)&valp->item.freq[frequi] - (long)valp),sizeof(valp->item.freq[frequi]));
        clear_hashtable_field(V->addrs,(long)((long)&addrp->item.freq[frequi] - (long)addrp),sizeof(addrp->item.freq[frequi]));
        clear_hashtable_field(V->txids,(long)((long)&tp->item.freq[frequi] - (long)tp),sizeof(tp->item.freq[frequi]));
        clear_hashtable_field(V->scripts,(long)((long)&sp->item.freq[frequi] - (long)sp),sizeof(sp->item.freq[frequi]));
        for (i=0; i<V->maxblocknum; i++)
            V->blockitems[i].freq[frequi] = 0;
        for (i=0; i<(1<<16); i++)
            V->txinditems[i].freq[frequi] = 0;
        for (i=0; i<(1<<16); i++)
            V->voutitems[i].freq[frequi] = 0;
    }
}

void update_huffitem(int32_t incr,struct huffitem *hip,uint32_t rawind,uint32_t hufftype,void *fullitem,long fullsize,int32_t wt)
{
    int32_t i;
    printf("update_huffitem rawind.%d type.%d full.%p size.%ld wt.%d\n",rawind,hufftype,fullitem,fullsize,wt);
    if ( fullitem != 0 )
        huff_iteminit(hip,(rawind << 3) | hufftype,fullitem,fullsize,wt);
    if ( incr > 0 )
    {
        for (i=0; i<(int32_t)(sizeof(hip->freq)/sizeof(*hip->freq)); i++)
            hip->freq[i] += incr;
    }
}

long emit_blockcheck(FILE *fp,uint64_t blocknum,int32_t restorepos)
{
    long retval,fpos;
    uint64_t blockcheck;
    fpos = ftell(fp);
    blockcheck = (~blocknum << 32) | blocknum;
    retval = fwrite(&blockcheck,1,sizeof(blockcheck),fp);
    if ( restorepos != 0 )
        fseek(fp,fpos,SEEK_SET);
    return(retval);
}

uint32_t load_blockcheck(FILE *fp,int32_t depth,char *coinstr)
{
    uint64_t blockcheck;
    uint32_t blocknum = 0;
    fseek(fp,0,SEEK_END);
    if ( ftell(fp) >= depth*sizeof(uint64_t) )
    {
        fseek(fp,-sizeof(uint64_t) * depth,SEEK_END);
        if ( fread(&blockcheck,1,sizeof(uint64_t),fp) != sizeof(blockcheck) || (uint32_t)(blockcheck >> 32) != ~(uint32_t)blockcheck )
            blocknum = 0;
        else
        {
            blocknum = (uint32_t)blockcheck;
            //printf("found valid marker.%s blocknum %llx -> %u\n",coinstr,(long long)blockcheck,blocknum);
        }
        fseek(fp,-sizeof(uint64_t) * depth,SEEK_END);
    }
    return(blocknum);
}

uint32_t setget_rawbits(uint32_t *rawbits,uint32_t size,uint32_t *blocknump,uint32_t checkpoints[3],uint16_t *numvinsp,uint16_t *numvoutsp,struct address_entry *vins,struct rawblock_voutdata *vouts)
{
    long i,n,incr,sizes[6];
    void *ptrs[6];
    uint32_t parsedsize = size;
    incr = n = 0;
    sizes[n] = sizeof(parsedsize), incr += sizes[n], ptrs[n++] = &parsedsize;
    sizes[n] = sizeof(*blocknump), incr += sizes[n], ptrs[n++] = blocknump;
    sizes[n] = sizeof(checkpoints[0]) * 3, incr += sizes[n], ptrs[n++] = checkpoints;
    sizes[n] = sizeof(*numvinsp), incr += sizes[n], ptrs[n++] = numvinsp;
    sizes[n] = sizeof(*numvoutsp), incr += sizes[n], ptrs[n++] = numvoutsp;
    sizes[n] = sizeof(*vins) * (*numvinsp), incr += sizes[n], ptrs[n++] = vins;
    //rawblock_voutdata *vp;//{ uint32_t tp_ind,vout,addr_ind,sp_ind; uint64_t value; };  // tp_ind is incrementing each time vout resets
    sizes[n] = sizeof(*vouts) * (*numvoutsp), incr += sizes[n], ptrs[n++] = vouts;
    if ( size == 0 )
    {
        for (i=0; i<n; i++)
            if ( sizes[i] != 0 )
                memcpy(&rawbits[size],ptrs[i],sizes[i]), size += (uint32_t)sizes[i];
        return(size);
    }
    else
    {
        size = 0;
        for (i=0; i<n; i++)
            if ( sizes[i] != 0 )
                memcpy(ptrs[i],&rawbits[size],sizes[i]), size += (uint32_t)sizes[i];
        return(parsedsize);
    }
}

int32_t parse_bitstream(struct compressionvars *V,uint8_t *rawbits,uint32_t size)
{
    int32_t retval = -1;
    uint16_t numvins,numvouts;
    uint32_t blocknum,parsedsize,checkpoints[3];
    parsedsize = setget_rawbits((uint32_t *)V->rawbits,size,&blocknum,checkpoints,&numvins,&numvouts,V->rawdata->vins,V->rawdata->vouts);
    if ( parsedsize == size )
    {
        V->rawdata->numvins = numvins, V->rawdata->numvouts = numvouts;
        return(size);
    } else printf("ERROR: parsedsize.%d != size.%d: ",parsedsize,size);
    printf("%d vins.%d vouts.%d: %d %d %d\n",blocknum,numvins,numvouts,checkpoints[0],checkpoints[1],checkpoints[2] );
    return(retval);
}

uint32_t load_bitstream(struct compressionvars *V,FILE *fp,int32_t breakflag)
{
    uint32_t size,count = 0;
    while ( fread(&size,1,sizeof(size),fp) == sizeof(size) )
    {
        printf("got size.%d\n",size);
        memcpy(V->rawbits,&size,sizeof(size));
        if ( fread((void *)((long)V->rawbits + sizeof(size)),1,size - sizeof(size),fp) != (size - sizeof(size)) || parse_bitstream(V,V->rawbits,size) < 0 )
            break;
        count++;
        if ( breakflag != 0 )
            break;
    }
    return(count);
}

int32_t emit_compressed_block(struct compressionvars *V,uint32_t blocknum,int32_t frequi)
{
    int32_t i,maxhuffinds;
    FILE *fps[3];
    uint32_t size,checkval,checkpoints[sizeof(fps)/sizeof(*fps)],offset,numhuffinds = 0;
    uint16_t numvins,numvouts;
    struct scriptinfo *sp = 0;
    struct txinfo *tp = 0;
    struct coinaddr *addrp = 0;
    struct valueinfo *valp = 0;
    struct huffcode *huff;
    struct huffitem **items;
    //struct rawblock_voutdata *vp;//{ uint32_t tp_ind,vout,addr_ind,sp_ind; uint64_t value; };
    //struct address_entry *bp;//{ uint64_t blocknum:32,txind:15,vinflag:1,v:14,spent:1,isinternal:1; };
    fps[0] = V->sfp, fps[1] = V->tfp, fps[2] = V->afp;
    if ( V->ofp != 0 )
    {
        offset = (uint32_t)ftell(V->fp);
        fseek(V->ofp,blocknum*sizeof(offset),SEEK_SET);
        fwrite(&offset,1,sizeof(offset),V->ofp);
        fflush(V->ofp);
        printf("[%s offset.%u %ld] ",V->coinstr,offset,ftell(V->ofp));
    }
    for (i=0; i<(int)(sizeof(fps)/sizeof(*fps)); i++)
    {
        if ( fps[i] != 0 )
        {
            checkpoints[i] = (uint32_t)ftell(fps[i]);
            emit_blockcheck(fps[i],blocknum,1); // will be overwritten next block, but allows resuming in case interrupted
            checkval = load_blockcheck(fps[i],1,V->coinstr);
            if ( checkval != blocknum )
                printf("fps[%d] %s.%u checkval mismatch %u != %u\n",i,V->coinstr,blocknum,checkval,blocknum);
            fflush(fps[i]);
        }
    }
    numvins = V->rawdata->numvins, numvouts = V->rawdata->numvouts;
    if ( numvins != V->rawdata->numvins || numvouts != V->rawdata->numvouts )
    {
        printf("vout overflow: numvins.%d V->rawdata->numvins.%d, numvouts.%d V->rawdata->numvouts.%d\n",numvins,V->rawdata->numvins,numvouts,V->rawdata->numvouts);
        exit(-1);
    }
    size = setget_rawbits((uint32_t *)V->rawbits,0,&blocknum,checkpoints,&numvins,&numvouts,V->rawdata->vins,V->rawdata->vouts);
    *(uint32_t *)V->rawbits = size, fwrite(V->rawbits,1,size,V->fp);
    emit_blockcheck(V->fp,ftell(fps[2]),0), emit_blockcheck(V->fp,ftell(fps[1]),0), emit_blockcheck(V->fp,ftell(fps[0]),0), emit_blockcheck(V->fp,blocknum,0);
    fflush(V->fp);
    parse_bitstream(V,V->rawbits,size);
   // printf("size.%ld numvins.%d numvouts.%d\n",size,numvins,numvouts);
    maxhuffinds = (int32_t)(V->addrs->numitems + V->values->numitems + V->txids->numitems + V->scripts->numitems);
    if ( 0 || maxhuffinds == 0 )
        return(0);
    items = calloc(maxhuffinds,sizeof(*items));
    for (i=0; i<numvouts; i++)
    {
        //if ( i != V->rawdata->vouts[i].vout ) this is flag of new tx
        //    printf("WARNING: i.%d != %d V->rawdata->vouts[].vout\n",i,V->rawdata->vouts[i].vout);
    }
    numhuffinds = 0;
    numhuffinds = gather_hashtable_field((void **)items,numhuffinds,maxhuffinds,V->values,(long)((long)&valp->item.freq[frequi] - (long)valp),sizeof(valp->item.freq[frequi]));
    numhuffinds = gather_hashtable_field((void **)items,numhuffinds,maxhuffinds,V->addrs,(long)((long)&addrp->item.freq[frequi] - (long)addrp),sizeof(addrp->item.freq[frequi]));
    numhuffinds = gather_hashtable_field((void **)items,numhuffinds,maxhuffinds,V->txids,(long)((long)&tp->item.freq[frequi] - (long)tp),sizeof(tp->item.freq[frequi]));
    numhuffinds = gather_hashtable_field((void **)items,numhuffinds,maxhuffinds,V->scripts,(long)((long)&sp->item.freq[frequi] - (long)sp),sizeof(sp->item.freq[frequi]));
    //fprintf(stderr,"items.%p numhuffinds.%d maxhuffinds.%d\n",items,numhuffinds,maxhuffinds);
    for (i=0; i<V->maxblocknum; i++)
    {
        if ( V->blockitems[i].freq[frequi] != 0 )
            items[numhuffinds++] = &V->blockitems[i];
    }
    for (i=0; i<(1<<16); i++)
        if ( V->txinditems[i].freq[frequi] != 0 )
            items[numhuffinds++] = &V->txinditems[i];
    for (i=0; i<(1<<16); i++)
        if ( V->voutitems[i].freq[frequi] != 0 )
            items[numhuffinds++] = &V->voutitems[i];
    if ( 0 && numhuffinds > 0 && (huff= huff_create((const struct huffitem **)items,numhuffinds,frequi)) != 0 )
    {
        /*for (i=num=0; i<len; i++)
         {
         huffind;
         num += hwrite(huff->items[c].codebits,huff->items[c].numbits,hp);
         }*/
        printf("numhuffinds.%d size.%d starting bits.%.0f -> %.0f [%.3f]\n",numhuffinds,size,huff->totalbytes/8,huff->totalbits/8,(double)huff->totalbytes/(huff->totalbits+1));
        //hrewind(hp);
        //dlen = huff_decode(huff,output,(int32_t)sizeof(output),hp);
        //output[num] = 0;

        hflush(V->fp,V->hp);
        hclear(V->hp);
        huff_clearstats(huff);
        huff_free(huff);
    } //else printf("error from huff_create %s.%u\n",coinstr,blocknum);
    free(items);
    return(numhuffinds);
}

struct address_entry *_update_entries(uint32_t *allocsizep,uint32_t *numentriesp,struct address_entry *entries,struct address_entry *entry)
{
    (*allocsizep) = ((*numentriesp)+1) * sizeof(*entries);
    entries = realloc(entries,*allocsizep);
    entries[(*numentriesp)++] = *entry;
    return(entries);
}

void update_coinaddr_entries(struct coinaddr *addrp,struct address_entry *entry)
{
    //addrp->allocsize = ((addrp->numentries+1) * sizeof(*entry));
    //addrp->entries = realloc(addrp->entries,addrp->allocsize);
    //addrp->entries[addrp->numentries++] = *entry;
    addrp->entries = _update_entries(&addrp->allocsize,&addrp->numentries,addrp->entries,entry);
}

void add_entry_to_tx(struct txinfo *tp,struct address_entry *entry)
{
    //tp->allocsize = ((tp->numentries+1) * sizeof(*entry));
    //tp->entries = realloc(tp->entries,tp->allocsize);
    //tp->entries[tp->numentries++] = *entry;
    tp->entries = _update_entries(&tp->allocsize,&tp->numentries,tp->entries,entry);
}

FILE *_open_varsfile(int32_t readonly,uint32_t *blocknump,char *fname,char *coinstr)
{
    FILE *fp = 0;
    if ( readonly != 0 )
    {
        if ( (fp = fopen(fname,"rb")) != 0 )
        {
            fseek(fp,0,SEEK_END);
            *blocknump = load_blockcheck(fp,1,coinstr);
            printf("opened %s blocknum.%d\n",fname,*blocknump);
            rewind(fp);
        }
    }
    else
    {
        if ( (fp = fopen(fname,"rb+")) == 0 )
        {
            fp = fopen(fname,"wb+");
            printf("created %s\n",fname);
            *blocknump = 0;
        }
        else
        {
            fseek(fp,0,SEEK_END);
            *blocknump = load_blockcheck(fp,1,coinstr);
            printf("opened %s blocknum.%d\n",fname,*blocknump);
            rewind(fp);
        }
    }
    return(fp);
}

int32_t load_reference_strings(uint32_t *blocknump,char *coinstr,struct hashtable *table,FILE *fp,int32_t isbinary)
{
    char str[65536];
    uint8_t data[8192];
    uint32_t *ptr;
    long endpos = 0;
    int32_t len,createdflag,count = 0;
    *blocknump = 0;
    if ( fp != 0 && table != 0 )
    {
        fseek(fp,-sizeof(uint64_t),SEEK_END);
        endpos = ftell(fp);
        rewind(fp);
        while ( ftell(fp) < endpos && load_vfilestr(&len,(isbinary != 0) ? (char *)data : str,fp) > 0 )
        {
            if ( isbinary != 0 )
                init_hexbytes_noT(str,data,len);
            if ( str[0] != 0 )
            {
                //printf("add.(%s)\n",str);
                ptr = add_hashtable(&createdflag,&table,str);
                if ( createdflag != 0 )
                    *ptr = ++count;
                else printf("WARNING: redundant entry in (%s).%d [%s]?\n",table->name,count,str);
            }
        }
    }
    *blocknump = load_blockcheck(fp,1,coinstr);
    printf("loaded %d to block.%u from hashtable.(%s) fpos.%ld vs endpos.%ld\n",count,*blocknump,table->name,ftell(fp),endpos);
    return(count);
}

void set_commpressionvars_fname(int32_t readonly,char *fname,char *coinstr,char *typestr,int32_t subgroup)
{
    char *dirname = (0*readonly != 0) ? "/Users/jimbolaptop/address" : "address";
    if ( subgroup < 0 )
        sprintf(fname,"%s/%s/%s.%s",dirname,coinstr,coinstr,typestr);
    else sprintf(fname,"%s/%s/%s/%s.%d",dirname,coinstr,typestr,coinstr,subgroup);
}

FILE *open_commpresionvars_file(int32_t readonly,struct compressionvars *V,uint32_t *checkpoints,struct hashtable *table,uint32_t *countp,uint32_t *blocknump,char *coinstr,char *typestr)
{
    char fname[1024];//,str[8192];
    uint32_t tmpblocknum,groupsize = BITSTREAM_GROUPSIZE(coinstr);
    FILE *fp,*tmpfp = 0;
    int32_t i,count = 0;
    if ( checkpoints != 0 )
        for (i=0; i<3; i++)
            checkpoints[i] = -1;
    if ( blocknump != 0 )
        *blocknump = -1;
    if ( countp != 0 )
        *countp = 0;
    if ( strcmp(typestr,"bitstream") != 0 )
    {
        set_commpressionvars_fname(readonly,fname,coinstr,typestr,-1);
        if ( readonly != 0 )
        {
            if ( (fp = fopen(fname,"rb")) != 0 )
            {
                printf("opened (%s) %p\n",fname,fp);
                if ( table != 0 )
                {
                    count = load_reference_strings(blocknump,coinstr,table,fp,strcmp(typestr,"addrs") != 0);
                    if ( countp != 0 )
                        *countp = count;
                }
            }
        }
        else
        {
            if ( 1 && (fp = fopen(fname,"rb+")) != 0 )
            {
                printf("opened (%s) %p\n",fname,fp);
                if ( table != 0 )
                {
                    count = load_reference_strings(blocknump,coinstr,table,fp,strcmp(typestr,"addrs") != 0);
                    if ( countp != 0 )
                        *countp = count;
                }
            }
            else fp = fopen(fname,"wb+");
        }
        return(fp);
    }
    else if ( 1 )
    {
        set_commpressionvars_fname(readonly,fname,coinstr,typestr,0);
        if ( readonly != 0 )
        {
            if ( (fp = fopen(fname,"rb")) != 0 )
            {
                
            }
        }
        else
        {
            if ( 1 && (fp = fopen(fname,"rb+")) != 0 )
            {
                
            }
            else fp = fopen(fname,"wb+");
        }
        if ( fp != 0 )
        {
            checkpoints[0] = load_blockcheck(fp,2,coinstr);
            checkpoints[1] = load_blockcheck(fp,3,coinstr);
            checkpoints[2] = load_blockcheck(fp,4,coinstr);
            V->prevblock = *blocknump = load_blockcheck(fp,1,coinstr); // set fpos
        }
        printf("Got checkpoints %u %u %u\n",checkpoints[0],checkpoints[1],checkpoints[2]);
        return(fp);
    }
    else
    {
        fp = 0;
        for (i=0; i<10000; i++)
        {
            set_commpressionvars_fname(readonly,fname,coinstr,typestr,i*groupsize);
            if ( (tmpfp= _open_varsfile(readonly,&tmpblocknum,fname,coinstr)) == 0 )
            {
                printf("error opening.(%s) tmpblocknum.%u\n",fname,tmpblocknum);
                if ( fp != 0 )
                    fclose(fp), fp = 0;
                *blocknump = -1;
                break;
            }
            else if ( tmpblocknum == 0 )
            {
                *blocknump = (i * groupsize) - 1;
                printf("opening.(%s) has blocknum of 0, set to %d\n",fname,*blocknump);
                if ( fp != 0 )
                    fclose(fp);
                fp = tmpfp, tmpfp = 0;
                break;
            }
            else
            {
                *blocknump = tmpblocknum;
                printf(">>>>>> opening.(%s) has blocknum of %d\n",fname,*blocknump);
                if ( fp != 0 )
                    fclose(fp);
                fp = tmpfp, tmpfp = 0;
                if ( checkpoints != 0 )
                {
                    checkpoints[0] = load_blockcheck(fp,2,coinstr);
                    checkpoints[1] = load_blockcheck(fp,3,coinstr);
                    checkpoints[2] = load_blockcheck(fp,4,coinstr);
                    V->prevblock = load_blockcheck(fp,1,coinstr); // set fpos
                }
                if ( tmpblocknum != (i*groupsize + groupsize-1) )
                {
                    printf("i.%d groupsize.%d not expected %d, break checkpoints.(%d %d %d)\n",i,groupsize,(i*groupsize + groupsize-1),checkpoints[0],checkpoints[1],checkpoints[2]);
                    break;
                }
            }
        }
        if ( i < 10000 )
            *countp = count = i;
        else if ( tmpfp != 0 )
            fclose(tmpfp), tmpfp = 0;
    }
    return(fp);
}

void init_ramchain(int32_t readonly,struct compressionvars *V)
{
    long size = 1;
    int32_t checkpoints[4],numblocks,numoffsets,numvalues = 0;
    uint64_t value;
    uint32_t offset;
    while ( V->vfp != 0 && fread(&value,1,sizeof(value),V->vfp) == sizeof(value) )
    {
        numvalues++;
    }
    numoffsets = 0;
    while ( V->ofp != 0 && fread(&offset,1,sizeof(offset),V->ofp) == sizeof(offset) )
    {
        if ( offset != 0 )
            numoffsets++;
    }
    if ( V->fp != 0 && readonly != 0 )
    {
        rewind(V->fp);
        int i;
        fread(V->rawbits,sizeof(uint32_t),64,V->fp);
        for (i=0; i<64; i++)
            printf("%08x ",((uint32_t *)V->rawbits)[i]);
        printf("first block\n"); getchar();
        rewind(V->fp);
        numblocks = 0;
        while ( (numblocks= load_bitstream(V,V->fp,1)) > 0 )
        {
            fread(checkpoints,1,sizeof(checkpoints),V->fp);
            printf("got numblocks.%d: numoffsets.%d size.%dblocknum.%d numvins.%d numvouts.%d | %d %d %d %d\n",numblocks,numoffsets,((uint32_t *)V->rawbits)[0],((uint32_t *)V->rawbits)[1],((uint32_t *)V->rawbits)[2],((uint32_t *)V->rawbits)[3],checkpoints[0],checkpoints[1],checkpoints[2],checkpoints[3]);
        }
        numblocks++;
    }
    printf("%s.%u: addrs.%d txids.%d scripts.%d numvalues.%d/%d: %s\n",V->coinstr,V->prevblock,V->addrind,V->txind,V->scriptind,numvalues,V->numvalues,_mbstr(size));
    if ( readonly != 0 )
        getchar();
}

void compressionvars_add_txout(struct rawblockdata *rp,char *coinstr,uint32_t tp_ind,uint32_t vout,uint32_t addr_ind,uint64_t value,uint32_t sp_ind)
{
    struct rawblock_voutdata *vp;
    vp = &rp->vouts[rp->numvouts++];
    vp->tp_ind = tp_ind;
    vp->vout = vout;
    vp->addr_ind = addr_ind;
    vp->value = value;
    vp->sp_ind = sp_ind;
}

void compressionvars_add_txin(struct rawblockdata *rp,char *coinstr,struct address_entry *bp)
{
    rp->vins[rp->numvins++] = *bp;
}

double estimate_completion(char *coinstr,double startmilli,int32_t processed,int32_t numleft)
{
    double elapsed,rate;
    if ( processed <= 0 )
        return(0.);
    elapsed = (milliseconds() - startmilli);
    rate = (elapsed / processed);
    if ( rate <= 0. )
        return(0.);
    //printf("numleft %d rate %f\n",numleft,rate);
    return(numleft * rate / 1000.);
}

uint32_t flush_compressionvars(struct compressionvars *V,uint32_t prevblocknum,uint32_t newblocknum,int32_t frequi)
{
    char fname[1024];
    uint32_t tmpblocknum,slice,numhuffinds;
    if ( prevblocknum == 0xffffffff )
        return(0);
    if ( V->firstblock == 0 && newblocknum > 0 )
        V->firstblock = newblocknum;
    printf("call emit\n");
    numhuffinds = emit_compressed_block(V,prevblocknum,frequi);
    printf("back\n");
    V->processed++;
    if ( V->disp != 0 )
    {
        sprintf(V->disp+strlen(V->disp),"-> numhuffs.%d max.%-4d %.1f %.1f est %.1f minutes\n%s F.%d NEWBLOCK.%u A%u T%u S%u numV.%d |",numhuffinds,V->maxitems,(double)(ftell(V->fp)+ftell(V->afp)+ftell(V->tfp)+ftell(V->sfp)+ftell(V->vfp))/(prevblocknum+1),(double)ftell(V->fp)/(prevblocknum+1),estimate_completion(V->coinstr,V->startmilli,V->processed,(int32_t)300000-prevblocknum)/60,V->coinstr,frequi,prevblocknum,V->addrind,V->txind,V->scriptind,V->numvalues);
        printf("%s",V->disp);
        V->disp[0] = 0;
    }
    if ( 0 && (newblocknum % BITSTREAM_GROUPSIZE(V->coinstr)) == 0 )
    {
        fclose(V->fp);
        set_commpressionvars_fname(0,fname,V->coinstr,"bitstream",newblocknum);
        if ( (V->fp= _open_varsfile(0,&tmpblocknum,fname,V->coinstr)) == 0 )
        {
            printf("couldnt open (%s) at newblocknum.%d\n",fname,newblocknum);
            exit(-1);
        }
    }
    calc_frequi(&slice,V->coinstr,newblocknum);
    clear_compressionvars(V,(newblocknum % slice) == 0,frequi);
    V->prevblock = newblocknum;
    return(newblocknum);
}

void init_compressionvars(int32_t readonly,struct compressionvars *V,char *coinstr,int32_t maxblocknum)
{
    struct coin_info *cp = get_coin_info(coinstr);
    struct coinaddr *addrp = 0;
    struct txinfo *tp = 0;
    struct scriptinfo *sp = 0;
    struct valueinfo *valp = 0;
    char fname[512];
    uint16_t s;
    uint32_t blocknums[4],i,checkpoints[4];
    if ( V->addrs == 0 )
    {
        strcpy(V->coinstr,coinstr);
        V->startmilli = milliseconds();
        if ( (V->maxblocknum= get_blockheight(cp)) == 0 )
            V->maxblocknum = maxblocknum;
        printf("init compression vars.%s: maxblocknum %d %d\n",coinstr,maxblocknum,get_blockheight(cp));
        V->buffer = calloc(1,1000000);
        V->disp = calloc(1,1000000);
        V->rawbits = calloc(1,1000000);
        V->rawdata = calloc(1,sizeof(*V->rawdata));
        V->hp = hopen(V->buffer,1000000);
        V->blockitems = calloc(V->maxblocknum,sizeof(*V->blockitems));
        V->txinditems = calloc(1<<16,sizeof(*V->txinditems));
        V->voutitems = calloc(1<<16,sizeof(*V->voutitems));
        /*for (i=0; i<V->maxblocknum; i++)
            update_huffitem(0,&V->blockitems[i],i,HUFF_BLOCKNUM,&i,sizeof(i),sizeof(uint32_t));
        for (s=0; s<=((1<<16)-2); s++)
        {
            update_huffitem(0,&V->txinditems[s],s,HUFF_TXIND,&s,sizeof(s),sizeof(uint16_t));
            update_huffitem(0,&V->voutitems[s],s,HUFF_VOUT,&s,sizeof(s),sizeof(uint16_t));
        }*/
        //V->values = hashtable_create("values",10,sizeof(*valp),((long)&valp->value - (long)valp),sizeof(valp->value),-1);
        V->values = hashtable_create("values",10,sizeof(*valp),sizeof(*valp),0,-1);
        V->addrs = hashtable_create("addrs",10,sizeof(*addrp),sizeof(*addrp),0,-1);
        V->txids = hashtable_create("txids",10,sizeof(*tp),sizeof(*tp),0,-1);
        V->scripts = hashtable_create("scripts",10,sizeof(*sp),sizeof(*sp),0,-1);
        //V->addrs = hashtable_create("addrs",100,sizeof(*addrp),((long)&addrp->addr[0] - (long)addrp),0,-1);
        //V->txids = hashtable_create("txids",100,sizeof(*tp),((long)&tp->txidstr[0] - (long)tp),0,-1);
        V->afp = open_commpresionvars_file(readonly,V,0,V->addrs,&V->addrind,&blocknums[1],coinstr,"addrs");
        V->tfp = open_commpresionvars_file(readonly,V,0,V->txids,&V->txind,&blocknums[2],coinstr,"txids");
        V->sfp = open_commpresionvars_file(readonly,V,0,V->scripts,&V->scriptind,&blocknums[3],coinstr,"scripts");
        V->vfp = open_commpresionvars_file(readonly,V,0,0,0,0,coinstr,"values");
        set_commpressionvars_fname(readonly,fname,coinstr,"offsets",-1);
        if ( (V->ofp= fopen(fname,"rb+")) == 0 )
        {
            if ( (V->ofp= fopen(fname,"wb")) != 0 )
            {
                uint32_t zero;
                for (i=0; i<V->maxblocknum*1.25; i++)
                    fwrite(&zero,1,sizeof(zero),V->ofp);
                fclose(V->ofp);
                V->ofp = fopen(fname,"rb+");
            }
        }
        V->fp = open_commpresionvars_file(readonly,V,checkpoints,0,&V->filecount,&blocknums[0],coinstr,"bitstream");
        if ( blocknums[0] == 0xffffffff )
            blocknums[0] = 0;
        for (i=1; i<4; i++)
        {
            printf("prev.%u blocknum.%u vs %u | checkpoint %u\n",V->prevblock,blocknums[i],blocknums[0],checkpoints[i-1]);
            if ( blocknums[i] == 0xffffffff )
                blocknums[i] = 0;
            if ( blocknums[i] != blocknums[0] )
                break;
        }
        if ( V->prevblock != 0xffffffff )
        {
            if ( i != 4 )
            {
                printf("mismatched blocknums in critical %s files: setting to last checkpoint (%u %u %u)\n",coinstr,checkpoints[0],checkpoints[1],checkpoints[2]);
                //exit(1);
                fseek(V->afp,checkpoints[0],SEEK_SET);
                fseek(V->tfp,checkpoints[1],SEEK_SET);
                fseek(V->sfp,checkpoints[2],SEEK_SET);
                //fseek(V->ofp,checkpoints[3],SEEK_SET);
                //fseek(V->ofp,sizeof(uint32_t)*(V->prevblock+1),SEEK_SET);
            } //else V->prevblock = load_bitstream(V,V->fp,0);
            init_ramchain(readonly,V);
        } else rewind(V->fp), rewind(V->afp), rewind(V->sfp), rewind(V->vfp), rewind(V->ofp);
    }
    if ( readonly != 0 )
        exit(1);
}

void *update_compressionvars_table(int32_t *createdflagp,uint32_t *indp,struct hashtable *table,char *str)
{
    void *ptr;
    ptr = add_hashtable(createdflagp,&table,str);
    //printf("call add_hashtable.(%s) %p created.%d\n",table->name,ptr,*createdflagp);
    if ( ptr == 0 )
        while ( 1 )
            sleep(1);
    if ( *createdflagp != 0 )
        (*indp)++;
    return(ptr);
}

int32_t expand_scriptdata(char *scriptstr,uint8_t *scriptdata,int32_t datalen)
{
    char *prefix,*suffix;
    int32_t mode;
    switch ( (mode= scriptdata[0]) )
    {
        case 's': prefix = "76a914", suffix = "88ac"; break;
        case 'm': prefix = "a9", suffix = "ac"; break;
        case 'r': prefix = "", suffix = "ac"; break;
        case ' ': prefix = "", suffix = ""; break;
        default: printf("unexpected scriptmode.(%d)\n",mode); prefix = "", suffix = ""; break;
    }
    strcpy(scriptstr,prefix);
    init_hexbytes_noT(scriptstr+strlen(scriptstr),scriptdata+1,datalen-1);
    if ( suffix[0] != 0 )
        strcat(scriptstr,suffix);
    return(mode);
}

int32_t calc_scriptmode(int32_t *datalenp,uint8_t scriptdata[4096],char *script,int32_t trimflag)
{
    int32_t len,mode = 0;
    len = (int32_t)strlen(script);
    *datalenp = 0;
    if ( strncmp(script,"76a914",6) == 0 && strcmp(script+len-4,"88ac") == 0 )
    {
        if ( trimflag != 0 )
        {
            script[len-4] = 0;
            script += 6;
        }
        mode = 's';
    }
    else if ( strcmp(script+len-2,"ac") == 0 )
    {
        if ( strncmp(script,"a9",2) == 0 )
        {
            if ( trimflag != 0 )
            {
                script[len-2] = 0;
                script += 2;
            }
            mode = 'm';
        }
        else
        {
            if ( trimflag != 0 )
                script[len-2] = 0;
            mode = 'r';
        }
    } else mode = ' ';
    if ( trimflag != 0 )
    {
        scriptdata[0] = mode;
        *datalenp = (int32_t)(strlen(script) >> 1) + 1;
        decode_hex(scriptdata+1,*datalenp - 1,script);
        //printf("set pubkey.(%s).%ld <- (%s)\n",pubkeystr,strlen(pubkeystr),script);
    }
    return(mode);
}

int32_t calc_binaryaddr(uint8_t *binaryaddr,char *base58)
{
    //static const char *Base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
     return(-1); // need to convert base58 str to binary
}

int32_t expand_binaryaddr(uint8_t *binaryaddr,char *base58)
{
    static const char *Base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    /*while(x > 0)
    {
        (x, remainder) = divide(x, 58)
        output_string.append(code_string[remainder])
    }
    
    repeat(number_of_leading_zero_bytes_in_hash)
    {
        output_string.append(code_string[0]);
    }
    
    output_string.reverse();*/
    
    return(-1); // need to convert base58 str to binary
}

void update_ramchain(struct compressionvars *V,char *coinstr,char *addr,struct address_entry *bp,uint64_t value,char *txidstr,char *script)
{
    char fname[512],valuestr[128];
    int32_t frequi,datalen,createdflag;
    uint8_t databuf[4096];
    struct coinaddr *addrp = 0;
    struct txinfo *tp = 0;
    struct scriptinfo *sp = 0;
    struct valueinfo *valp = 0;
   // printf("update ramchain.(%s) addr.(%s) block.%d vin.%d %p %p\n",coinstr,addr,bp->blocknum,bp->vinflag,txidstr,script);
    if ( V->fp == 0 )
    {
        if ( IS_LIBTEST != 7 )
        {
            sprintf(fname,"address/%s/%s",V->coinstr,addr);
            if ( (V->fp= fopen(fname,"rb+")) == 0 )
                V->fp = fopen(fname,"wb+");
            else fseek(V->fp,0,SEEK_END);
        }
        else init_compressionvars(0,V,coinstr,500000);
    }
    if ( V->fp != 0 )
    {
printf("update compressionvars vinflag.%d\n",bp->vinflag);
        if ( bp->vinflag == 0 )
        {
            addrp = update_compressionvars_table(&createdflag,&V->addrind,V->addrs,addr);
printf("addrp.%p created.%d\n",addrp,createdflag);
            if ( addrp == 0 )
                exit(-1);
            if ( createdflag != 0 )
            {
                if ( V->afp != 0 )
                {
                    if ( 0 && calc_binaryaddr(addrp->binaryaddr,addr) <= sizeof(addrp->binaryaddr) )
                        fwrite(addrp->binaryaddr,1,sizeof(addrp->binaryaddr),V->afp);
                    else save_vfilestr(V->afp,addr);
                }
                update_coinaddr_entries(addrp,bp);
            }
            //else update_huffitem(1,&addrp->item,addrp->ind,HUFF_COINADDR,0,0,sizeof(uint32_t));
            update_huffitem(1,&addrp->item,addrp->ind,HUFF_COINADDR,addr,0,sizeof(uint32_t));
            if ( txidstr != 0 && script != 0 && value != 0 )
            {
printf("txid.(%s) %s\n",txidstr,script);
                frequi = calc_frequi(0,V->coinstr,V->prevblock);
                if ( bp->blocknum != V->prevblock )
                    V->prevblock = flush_compressionvars(V,V->prevblock,bp->blocknum,frequi);
            printf("update value %.8f %p\n",dstr(value),&value);
                if ( V->vfp != 0 )
                    fwrite(&value,1,sizeof(value),V->vfp);
                if ( 1 ) // problem with binary hashval mode
                {
                    expand_nxt64bits(valuestr,value);
                    valp = update_compressionvars_table(&createdflag,&V->valueind,V->values,valuestr);//(void *)&value);
                    //valp = update_compressionvars_table(&createdflag,&V->valueind,V->values,(void *)&value);
                    if ( createdflag != 0 )
                    {
                        V->numvalues++;
                    }
                   // else update_huffitem(1,&valp->item,valp->ind,HUFF_VALUE,0,0,sizeof(uint64_t));
                    update_huffitem(1,&valp->item,valp->ind,HUFF_VALUE,(void *)&value,sizeof(value),sizeof(uint64_t));
                }
                tp = update_compressionvars_table(&createdflag,&V->txind,V->txids,txidstr);
                if ( createdflag != 0 )
                {
                    datalen = (uint32_t)(strlen(txidstr) >> 1);
                    decode_hex(databuf,datalen,txidstr);
                    if ( V->tfp != 0 )
                        emit_varint(V->tfp,datalen), fwrite(databuf,1,datalen,V->tfp);
                }
                //else update_huffitem(1,&tp->item,tp->ind,HUFF_TXID,0,0,sizeof(uint32_t));
                update_huffitem(1,&tp->item,tp->ind,HUFF_TXID,tp->txidstr,0,sizeof(uint32_t));
                sp = update_compressionvars_table(&createdflag,&V->scriptind,V->scripts,script);
                if ( createdflag != 0 ) // indicates just created
                {
                    sp->mode = calc_scriptmode(&datalen,databuf,script,1);
                    sp->addrind = addrp->ind;
                    if ( V->sfp != 0 )
                        emit_varint(V->sfp,datalen), fwrite(databuf,1,datalen,V->sfp);
                }
                //else update_huffitem(1,&sp->item,sp->ind,HUFF_SCRIPT,0,0,sizeof(uint32_t));
                update_huffitem(1,&sp->item,sp->ind,HUFF_SCRIPT,sp->scriptstr,0,sizeof(uint32_t));
                if ( 0 && V->disp != 0 )
                    sprintf(V->disp+strlen(V->disp),"{A%d T%d.%d S%d %.8f} ",V->addrind,V->txind,bp->v,V->scriptind,dstr(value));
                compressionvars_add_txout(V->rawdata,V->coinstr,tp->ind,bp->v,addrp->ind,value,sp->ind);
            }
            else if ( txidstr != 0 ) // dereferenced (blocknum, txind, v)
            {
                uint16_t s;
                uint32_t tmp;
                add_entry_to_tx(tp,bp);
                if ( 0 && V->disp != 0 )
                    sprintf(V->disp+strlen(V->disp),"[%d %d %d] ",bp->blocknum,bp->txind,bp->v);
                compressionvars_add_txin(V->rawdata,V->coinstr,bp);
                tmp = bp->blocknum, update_huffitem(1,&V->blockitems[bp->blocknum],bp->blocknum,HUFF_BLOCKNUM,&tmp,sizeof(tmp),sizeof(uint32_t));
                s = bp->txind, update_huffitem(1,&V->txinditems[bp->txind],bp->txind,HUFF_TXIND,&s,sizeof(s),sizeof(uint16_t));
                s = bp->v, update_huffitem(1,&V->voutitems[bp->v],bp->v,HUFF_VOUT,&s,sizeof(s),sizeof(uint16_t));
            }
            V->maxitems++;
        }
        else
        {
            // vin txid:vin is dereferenced above
            //sprintf(V->disp+strlen(V->disp),"(%d %d %d) ",bp->blocknum,bp->txind,bp->v);
        }
        if ( IS_LIBTEST != 7 )
            fclose(V->fp);
    }
}

int main(int argc,const char *argv[])
{
    FILE *fp;
    cJSON *json = 0;
    int32_t retval;
    char ipaddr[64],*oldport,*newport,portstr[64],*retstr;
   // if ( Debuglevel > 0 )
#ifndef __APPLE__
    if ( 1 && argc > 1 && strcmp(argv[1],"genfiles") == 0 )
#endif
    {
        uint32_t process_coinblocks(char *coinstr);
        retval = SuperNET_start("SuperNET.conf","127.0.0.1");
        printf("process coinblocks\n");
        process_coinblocks((char *)argv[2]);
        getchar();
    }
#ifdef fortesting
    if ( 0 )
    {
        void huff_iteminit(struct huffitem *hip,void *ptr,int32_t size,int32_t isptr,int32_t ishex);
        char *p,buff[1024];//,*str = "this is an example for huffman encoding";
        int i,c,n,numinds = 256;
        int probs[256];
        //struct huffcode *huff;
        struct huffitem *items = calloc(numinds,sizeof(*items));
        int testhuffcode(char *str,struct huffitem *freqs,int32_t numinds);
        for (i=0; i<numinds; i++)
            huff_iteminit(&items[i],&i,1,0,0);
        while ( 1 )
        {
            for (i=0; i<256; i++)
                probs[i] = ((rand()>>8) % 1000);
            for (i=n=0; i<128; i++)
            {
                c = (rand() >> 8) & 0xff;
                while ( c > 0 && ((rand()>>8) % 1000) > probs[c] )
                {
                    buff[n++] = (c % 64) + ' ';
                    if ( n >= sizeof(buff)-1 )
                        break;
                }
            }
            buff[n] = 0;
            for (i=0; i<numinds; i++)
                items[i].freq = 0;
            p = buff;
            while ( *p != '\0' )
                items[*p++].freq++;
            testhuffcode(0,items,numinds);
            fprintf(stderr,"*");
        }
        //getchar();
    }
#endif
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
    if ( (fp= fopen("horrible.hack","wb+")) != 0 )
    {
        fwrite(&retval,1,sizeof(retval),fp);
        fclose(fp);
    }
    if ( Debuglevel > 0 )
        system("git log | head -n 1");
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
