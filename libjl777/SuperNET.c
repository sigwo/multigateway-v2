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
#include "uthash.h"

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

/*#define HUFF_VALUE 0
#define HUFF_COINADDR 1
#define HUFF_TXID 2
#define HUFF_SCRIPT 3
#define HUFF_BLOCKNUM 4
#define HUFF_TXIND 5
#define HUFF_VOUT 6
#define HUFF_RESERVED 7*/

//int32_t clear_hashtable_field(struct hashtable *hp,long offset,long fieldsize);
//int32_t gather_hashtable_field(void **items,int32_t numitems,int32_t maxitems,struct hashtable *hp,long offset,long fieldsize);
//struct hashtable *hashtable_create(char *name,int64_t hashsize,long structsize,long keyoffset,long keysize,long modifiedoffset);
//void *add_hashtable(int32_t *createdflagp,struct hashtable **hp_ptr,char *key);
//void **hashtable_gather_modified(int64_t *changedp,struct hashtable *hp,int32_t forceflag);
struct huffcode *huff_create(const struct huffitem **items,int32_t numinds,int32_t frequi);
void huff_iteminit(struct huffitem *hip,uint32_t huffind,void *ptr,long size,long wt);
void huff_free(struct huffcode *huff);
void huff_clearstats(struct huffcode *huff);
char *_mbstr(double n);
int32_t save_vfilestr(FILE *fp,char *str);
int32_t load_vfilestr(int32_t *lenp,char *str,FILE *fp,int32_t maxlen);
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

struct coinaddrinfo
{
    uint32_t numentries,allocsize;
    uint8_t binaryaddr[24];
    struct address_entry *entries;
    struct huffitem item;
};

struct valueinfo
{
    uint64_t value;
    struct huffitem item;
};

struct scriptinfo
{
    uint32_t addrhuffind;
    char mode;
    struct huffitem item;
};

struct txinfo
{
    uint32_t allocsize,numentries;
    uint16_t numvouts,numvins;
    struct address_entry *entries;
    struct huffitem item;
};

struct blockinfo { uint32_t firstvout,firstvin; }; // minimal info needed each block's VOUTS_count and VINS_count
struct rawblock_voutdata { uint32_t tp_ind,vout,addr_ind,sp_ind; uint64_t value; };

void set_commpressionvars_fname(int32_t readonly,char *fname,char *coinstr,char *typestr,int32_t subgroup)
{
    char *dirname = (1*readonly != 0) ? "/Users/jimbolaptop/ramchains" : "ramchains";
    if ( subgroup < 0 )
        sprintf(fname,"%s/%s/%s.%s",dirname,coinstr,coinstr,typestr);
    else sprintf(fname,"%s/%s/%s/%s.%d",dirname,coinstr,typestr,coinstr,subgroup);
}

int32_t check_for_blockcheck(FILE *fp)
{
    long fpos;
    uint64_t blockcheck;
    fpos = ftell(fp);
    fread(&blockcheck,1,sizeof(blockcheck),fp);
    if ( (uint32_t)(blockcheck >> 32) == ~(uint32_t)blockcheck )
        return(1);
    fseek(fp,fpos,SEEK_SET);
    return(0);
}

long emit_blockcheck(FILE *fp,uint64_t blocknum)
{
    long fpos,retval = 0;
    uint64_t blockcheck;
    if ( fp != 0 )
    {
        /*fseek(fp,0,SEEK_END);
        fpos = ftell(fp) - sizeof(blockcheck);
        if ( fpos < 0 )
            fpos = 0, rewind(fp);
        else if ( check_for_blockcheck(fp) != 0 )
            fseek(fp,fpos,SEEK_SET);*/
        fpos = ftell(fp);
        blockcheck = (~blocknum << 32) | blocknum;
        retval = fwrite(&blockcheck,1,sizeof(blockcheck),fp);
        fseek(fp,fpos,SEEK_SET);
        fflush(fp);
    }
    return(retval);
}

uint32_t load_blockcheck(FILE *fp)
{
    long fpos;
    uint64_t blockcheck;
    uint32_t blocknum = 0;
    fseek(fp,0,SEEK_END);
    fpos = ftell(fp);
    if ( fpos >= sizeof(blockcheck) )
    {
        fpos -= sizeof(blockcheck);
        fseek(fp,fpos,SEEK_SET);
    } else rewind(fp);
    if ( fread(&blockcheck,1,sizeof(blockcheck),fp) != sizeof(blockcheck) || (uint32_t)(blockcheck >> 32) != ~(uint32_t)blockcheck )
        blocknum = 0;
    else
    {
        blocknum = (uint32_t)blockcheck;
        fpos = ftell(fp);
        fseek(fp,fpos-sizeof(blockcheck),SEEK_SET);
        //printf("found valid marker blocknum %llx -> %u endpos.%ld fpos.%ld\n",(long long)blockcheck,blocknum,fpos,ftell(fp));
    }
    //fseek(fp,0,SEEK_END);
    //fpos = ftell(fp);
    //fseek(fp,fpos-sizeof(blockcheck),SEEK_SET);
    return(blocknum);
}

FILE *_open_varsfile(int32_t readonly,uint32_t *blocknump,char *fname,char *coinstr)
{
    FILE *fp = 0;
    if ( readonly != 0 )
    {
        if ( (fp = fopen(fname,"rb")) != 0 )
        {
            fseek(fp,0,SEEK_END);
            *blocknump = load_blockcheck(fp);
            printf("opened %s blocknum.%d\n",fname,*blocknump);
            rewind(fp);
        }
    }
    else
    {
        if ( (fp = fopen(fname,"rb+")) == 0 )
        {
            if ( (fp = fopen(fname,"wb")) == 0 )
            {
                printf("couldnt create (%s)\n",fname);
                while ( 1 ) sleep (60);
            }
            printf("created %s -> fp.%p\n",fname,fp);
            *blocknump = 0;
        }
        else
        {
            fseek(fp,0,SEEK_END);
            *blocknump = load_blockcheck(fp);
            printf("opened %s blocknum.%d\n",fname,*blocknump);
            rewind(fp);
        }
    }
    return(fp);
}

struct huffitem *update_compressionvars_table(int32_t *createdflagp,struct bitstream_file *bfp,char *str)
{
    struct huffitem *item;
    int32_t len;
    HASH_FIND_STR(bfp->dataptr,str,item);
    if ( item == 0 )
    {
        len = (int32_t)strlen(str);
        item = calloc(1,bfp->itemsize + len + 1);
        strcpy(item->str,str);
        //printf("%s: add.(%s)\n",bfp->typestr,str);
        HASH_ADD_STR(bfp->dataptr,str,item);
        huff_iteminit(item,(++bfp->ind<<3) | bfp->huffid,str,0,bfp->huffwt);
        *createdflagp = 1;
    } else *createdflagp = 0;
    return(item);
}

int32_t append_to_streamfile(struct bitstream_file *bfp,uint32_t blocknum,void *newdata,uint32_t num,int32_t flushflag)
{
    unsigned char databuf[8192];
    long n,fpos,startpos = ((long)bfp->ind * bfp->itemsize);
    void *startptr;
    FILE *fp;
    if ( (newdata == 0 || num == 0) && flushflag != 0 && (fp= bfp->fp) != 0 )
    {
        if ( blocknum != 0xffffffff )
        {
            emit_blockcheck(fp,blocknum); // will be overwritten next block, but allows resuming in case interrupted
            //printf("emit blockcheck.%d for %s from %u fpos %ld %d\n",blocknum,bfp->fname,bfp->blocknum,ftell(fp),load_blockcheck(fp));
            bfp->blocknum = blocknum;
        }
        return(0);
    }
    bfp->ind += num;
    if ( bfp->nomemstructs == 0 )
    {
        bfp->dataptr = realloc(bfp->dataptr,bfp->itemsize * bfp->ind);
        startptr = (void *)((long)bfp->dataptr + startpos);
    } else startptr = databuf;
    memcpy(startptr,newdata,num * bfp->itemsize);
    if ( blocknum == 0xffffffff )
        return(0);
    //force_fpos(bfp->fname,&bfp->fp,startpos);
    fseek(bfp->fp,startpos,SEEK_SET);
    if ( (fp= bfp->fp) != 0 && (fpos= ftell(fp)) == startpos )
    {
        if ( (n= fwrite(startptr,bfp->itemsize,num,fp)) != num )
            fprintf(stderr,"FWRITE ERROR %ld (%s) block.%u startpos.%ld num.%d itemsize.%ld\n",n,bfp->fname,blocknum,startpos,num,bfp->itemsize);
        else
        {
            if ( flushflag != 0 )
            {
                emit_blockcheck(bfp->fp,blocknum); // will be overwritten next block, but allows resuming in case interrupted
                //printf("emit blockcheck.%d for %s from %u fpos %ld %d\n",blocknum,bfp->fname,bfp->blocknum,ftell(fp),load_blockcheck(fp));
                bfp->blocknum = blocknum;
            }
            return(0);
        }
    } else fprintf(stderr,"append_to_filedata.(%s) block.%u error: fp.%p fpos.%ld vs startpos.%ld\n",bfp->fname,blocknum,fp,fpos,startpos);
    while ( 1 )
        sleep(1);
    exit(-1); // to get here probably out of disk space, abort is best
}

void update_huffitem(int32_t incr,struct huffitem *hip,uint32_t huffind,void *fullitem,long fullsize,int32_t wt)
{
    int32_t i;
    //printf("update_huffitem rawind.%d type.%d full.%p size.%ld wt.%d\n",rawind,hufftype,fullitem,fullsize,wt);
    if ( fullitem != 0 && hip->wt == 0 )
        huff_iteminit(hip,huffind,fullitem,fullsize,wt);
    if ( incr > 0 )
    {
        for (i=0; i<(int32_t)(sizeof(hip->freq)/sizeof(*hip->freq)); i++)
            hip->freq[i] += incr;
    }
}

void update_bitstream(struct bitstream_file *bfp,uint32_t blocknum)
{
    bfp->blocknum = blocknum;
}

void *update_bitstream_file(int32_t *createdflagp,struct bitstream_file *bfp,uint32_t blocknum,void *data,int32_t datalen,char *str)
{
    struct huffitem *item = 0;
    uint32_t huffind,rawind;
    int32_t createdflag = 0;
    if ( blocknum != 0xffffffff )
        bfp->blocknum = blocknum;
    if ( (bfp->mode & BITSTREAM_UNIQUE) != 0 ) // "addr", "txid", "script", "value"
    {
        item = update_compressionvars_table(&createdflag,bfp,str);
        if ( item != 0 && createdflag != 0 )
        {
            if ( blocknum != 0xffffffff && bfp->fp != 0 && (bfp->mode & BITSTREAM_STATSONLY) == 0 )
            {
                if ( data == 0 && str != 0 )
                    data = (uint8_t *)str, datalen = (int32_t)strlen(str);
                if ( data != 0 && datalen != 0 )
                {
                    //printf("%s: ",bfp->typestr);
                    if ( (bfp->mode & (BITSTREAM_STRING|BITSTREAM_HEXSTR)) != 0 )
                    {
                        //printf("%s: %d -> fpos.%ld ",bfp->typestr,datalen,ftell(bfp->fp));
                        emit_varint(bfp->fp,datalen);
                    }
                    if ( 0 )
                    {
                        char tmp[8192];
                        if ( str == 0 || str[0] == 0 )
                            init_hexbytes_noT(tmp,data,datalen);
                        else strcpy(tmp,str);
                        printf("(%s) -> fpos.%ld ",tmp,ftell(bfp->fp));
                    }
                    if ( fwrite(data,1,datalen,bfp->fp) != datalen )
                    {
                        printf("error writing %d bytes to %s\n",datalen,bfp->fname);
                        exit(-1);
                    }
                    //printf("block.%u -> fpos.%ld ",blocknum,ftell(bfp->fp));
                    emit_blockcheck(bfp->fp,blocknum);
                    //printf("curpos.%ld\n",ftell(bfp->fp));
                } else printf("warning: bfp[%d] had no data in block.%u\n",bfp->huffid,blocknum);
            }
        }
    }
    else if ( bfp->fp != 0 ) // "blocks", "vins", "vouts", "bitstream"
    {
        if ( blocknum != 0xffffffff && (bfp->mode & BITSTREAM_COMPRESSED) != 0 ) // "bitstream"
            update_bitstream(bfp,blocknum);
        else append_to_streamfile(bfp,blocknum,data,1,1);
    }
    else
    {
        uint8_t c; uint16_t s;
        rawind = 0;
        ++bfp->ind;
        switch ( bfp->itemsize )
        {
            case sizeof(uint32_t): memcpy(&rawind,data,bfp->itemsize); break;
            case sizeof(uint16_t): memcpy(&s,data,bfp->itemsize), rawind = s; break;
            case sizeof(uint8_t): c = *(uint8_t *)data, rawind = c; break;
            default: rawind = 0; printf("illegal itemsize.%ld\n",bfp->itemsize);
        }
        memcpy(&rawind,data,bfp->itemsize);
        if ( bfp->nomemstructs == 0 )
        {
            if ( rawind < bfp->maxitems ) // "inblock", "intxind", "invout"
            {
                huffind = (rawind << 3) | bfp->huffid;
                item = &bfp->dataptr[rawind];
                if ( item->wt == 0 )
                    huff_iteminit(item,huffind,(void *)&huffind,sizeof(huffind),bfp->huffwt);
            } else printf("rawind %d too big for %s %u\n",rawind,bfp->fname,bfp->maxitems);
        }
    }
    if ( item != 0 && bfp->nomemstructs == 0 )
        update_huffitem(1,item,item->huffind,0,0,bfp->huffwt);
    *createdflagp = createdflag;
    return(item);
}

long get_endofdata(long *eofposp,FILE *fp)
{
    long endpos;
    fseek(fp,0,SEEK_END);
    *eofposp = ftell(fp);
    fseek(fp,-sizeof(uint64_t),SEEK_END);
    endpos = ftell(fp);
    rewind(fp);
    return(endpos);
}

int32_t expand_scriptdata(uint32_t *addrhuffindp,char *scriptstr,uint8_t *scriptdata,int32_t datalen)
{
    char *prefix,*suffix;
    int32_t mode,n;
    uint32_t addrhuffind = 0;
    for (n=0; n<4; n++)
        addrhuffind |= scriptdata[n], addrhuffind <<= 8;
    switch ( (mode= scriptdata[n++]) )
    {
        case 's': prefix = "76a914", suffix = "88ac"; break;
        case 'm': prefix = "a9", suffix = "ac"; break;
        case 'r': prefix = "", suffix = "ac"; break;
        case ' ': prefix = "", suffix = ""; break;
        default: printf("unexpected scriptmode.(%d)\n",mode); prefix = "", suffix = ""; break;
    }
    strcpy(scriptstr,prefix);
    init_hexbytes_noT(scriptstr+strlen(scriptstr),scriptdata+n,datalen-n);
    if ( suffix[0] != 0 )
        strcat(scriptstr,suffix);
    return(mode);
}

int32_t calc_scriptmode(int32_t *datalenp,uint8_t scriptdata[4096],char *script,int32_t trimflag,uint32_t addrhuffind)
{
    int32_t n,len,mode = 0;
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
        for (n=0; n<4; n++)
            scriptdata[n] = (addrhuffind & 0xff), addrhuffind >>= 8;
        scriptdata[n++] = mode;
        len = (int32_t)(strlen(script) >> 1);
        decode_hex(scriptdata+n,len,script);
        (*datalenp) = (len + n);
        //printf("set pubkey.(%s).%ld <- (%s)\n",pubkeystr,strlen(pubkeystr),script);
    }
    return(mode);
}

int32_t load_reference_strings(struct compressionvars *V,struct bitstream_file *bfp,int32_t isbinary)
{
    FILE *fp;
    char str[65536],mode = 0;
    uint8_t data[32768];
    uint32_t addrhuffind = 0;
    struct huffitem *item;
    struct scriptinfo *sp;
    long remaining,eofpos,endpos = 0;
    int32_t len,maxlen,createdflag,n,count = 0;
    n = 0;
    if ( (fp= bfp->fp) != 0 )
    {
        endpos = get_endofdata(&eofpos,fp);
        maxlen = (int32_t)sizeof(data)-1;
        while ( ftell(fp) < endpos && load_vfilestr(&len,(isbinary != 0) ? (char *)data : str,fp,maxlen) > 0 )
        {
            //printf("isbinary.%d: len.%d\n",isbinary,len);
            if ( isbinary != 0 )
            {
                if ( (bfp->mode & BITSTREAM_SCRIPT) != 0 )
                    mode = expand_scriptdata(&addrhuffind,str,data,len);
                else init_hexbytes_noT(str,data,len);
            }
            if ( str[0] != 0 )
            {
                //printf("add.(%s)\n",str);
                if ( isbinary != 0 )
                    item = update_bitstream_file(&createdflag,bfp,0xffffffff,data,len,str);
                else item = update_bitstream_file(&createdflag,bfp,0xffffffff,0,0,str);
                if ( (bfp->mode & BITSTREAM_SCRIPT) != 0 )
                {
                    sp = (struct scriptinfo *)item;
                    sp->mode = mode;
                    sp->addrhuffind = addrhuffind;
                }
                if ( createdflag == 0 )
                    printf("WARNING: redundant entry in (%s).%d [%s]?\n",bfp->fname,count,str);
                count++;
            }
            remaining = (endpos - ftell(fp));
            if ( remaining < sizeof(data) )
                maxlen = (int32_t)(endpos - ftell(fp));
        }
    }
    bfp->checkblock = load_blockcheck(bfp->fp);
    printf("loaded %d to block.%u from hashtable.(%s) fpos.%ld vs endpos.%ld | numblockchecks.%d\n",count,bfp->checkblock,bfp->fname,ftell(fp),eofpos,n);
    return(count);
}

void update_vinsbfp(struct compressionvars *V,struct bitstream_file *bfp,struct address_entry *bp,uint32_t blocknum)
{
    uint16_t s; uint32_t tmp;
    int32_t createdflag;
//    printf("spent block.%u txind.%d vout.%d\n",bp->blocknum,bp->txind,bp->v);
    if ( blocknum != 0xffffffff )
        update_bitstream_file(&createdflag,bfp,blocknum,bp,sizeof(*bp),0);
    tmp = bp->blocknum, update_bitstream_file(&createdflag,V->bfps[V->inblockbfp],blocknum,&tmp,sizeof(tmp),0);
    s = bp->txind, update_bitstream_file(&createdflag,V->bfps[V->txinbfp],blocknum,&s,sizeof(s),0);
    s = bp->v, update_bitstream_file(&createdflag,V->bfps[V->invoutbfp],blocknum,&s,sizeof(s),0);
}

int32_t load_fixed_fields(struct compressionvars *V,struct bitstream_file *bfp)
{
    void *ptr;
    char hexstr[16385];
    uint8_t data[8192];
    int32_t createdflag,count = 0;
    long eofpos,endpos,itemsize;
    endpos = get_endofdata(&eofpos,bfp->fp);
    if ( bfp->itemsize >= sizeof(data) )
    {
        printf("bfp.%s itemsize.%ld too big\n",bfp->typestr,bfp->itemsize);
        exit(-1);
    }
    if ( (bfp->mode & BITSTREAM_VALUE) != 0 )
        itemsize = sizeof(uint64_t);
    else itemsize = bfp->itemsize;
    while ( (ftell(bfp->fp)+bfp->itemsize) <= endpos && fread(data,1,itemsize,bfp->fp) == itemsize )
    {
        init_hexbytes_noT(hexstr,data,itemsize);
        ptr = update_bitstream_file(&createdflag,bfp,0xffffffff,data,(int32_t)itemsize,hexstr);
        if ( (bfp->mode & BITSTREAM_VALUE) != 0 )
            memcpy(&((struct valueinfo *)ptr)->value,data,itemsize);
        else if ( (bfp->mode & BITSTREAM_VINS) != 0 )
            update_vinsbfp(V,bfp,(void *)data,0xffffffff);
    }
    return(count);
}

int32_t checkblock(struct blockinfo *current,struct blockinfo *prev,uint32_t blocknum)
{
    int32_t numvins,numvouts;
    //return((abs((int)~(blockcheck>>32)-blocknum)+abs((int)blockcheck-blocknum)));
    if ( prev != 0 )
    {
        if ( (numvins= (current->firstvin - prev->firstvin)) < 0 || (numvouts= (current->firstvout - prev->firstvout)) < 0 )
            return(1);
       // printf("block.%d: vins.(%d %d) vouts.(%d %d)\n",blocknum-1,prev->firstvin,numvins,prev->firstvout,numvouts);
    }
    return(0);
}

int32_t scan_ramchain(struct compressionvars *V)
{
    int i,checkval,errs = 0;
    //uint64_t blockcheck;
    struct blockinfo B,prevB;
    struct bitstream_file *bfp;
    memset(&prevB,0,sizeof(prevB));
    bfp = V->bfps[0];
    if ( bfp->fp == 0 )
        return(-1);
    rewind(bfp->fp);
    for (i=0; i<bfp->blocknum; i++)
    {
        fread(&B,1,sizeof(B),bfp->fp);
        checkval = checkblock(&B,i==0?0:&prevB,i);
        if ( checkval != 0 )
            printf("%i: %d %d | %s\n",i,B.firstvout,B.firstvin,checkval!=0?"ERROR":"OK");
        prevB = B;
        errs += (checkval != 0);
    }
    //uint32_t valuebfp,inblockbfp,txinbfp,invoutbfp,addrbfp,txidbfp,scriptbfp,voutsbfp,vinsbfp,bitstream,numbfps;
    printf("scan_ramchain %s: errs.%d blocks.%u values.%u addrs.%u txids.%u scripts.%u vouts.%u vins.%u | VIN block.%u txind.%u v.%u\n",bfp->coinstr,errs,bfp->blocknum,V->bfps[V->valuebfp]->ind,V->bfps[V->addrbfp]->ind,V->bfps[V->txidbfp]->ind,V->bfps[V->scriptbfp]->ind,V->bfps[V->voutsbfp]->ind,V->bfps[V->vinsbfp]->ind,V->bfps[V->inblockbfp]->ind,V->bfps[V->txinbfp]->ind,V->bfps[V->invoutbfp]->ind);
    getchar();
    return(errs);
}

struct bitstream_file *init_bitstream_file(struct compressionvars *V,int32_t huffid,int32_t mode,int32_t readonly,char *coinstr,char *typestr,long itemsize,uint32_t refblock,long huffwt)
{
    struct bitstream_file *bfp = calloc(1,sizeof(*bfp));
    int32_t numitems;
    bfp->huffid = huffid;
    bfp->nomemstructs = !readonly;
    bfp->mode = mode;
    if ( (bfp->huffwt = (uint32_t)huffwt) == 0 )
        bfp->huffwt = (uint32_t)itemsize;
    bfp->itemsize = itemsize;
    bfp->refblock = refblock;
    strcpy(bfp->coinstr,coinstr);
    strcpy(bfp->typestr,typestr);
    if ( (mode & BITSTREAM_STATSONLY) != 0 ) // needs to be unique filtered, so use hashtable
    {
        bfp->maxitems = refblock;
        if ( bfp->nomemstructs == 0 )
        {
            if ( itemsize == sizeof(uint32_t)/8 )
                numitems = bfp->maxitems;
            else if ( itemsize == sizeof(int16_t)/8 )
                numitems = (1<<16);
            else { printf("unsupported itemsize of statsonly: %ld\n",itemsize); exit(-1); }
            bfp->dataptr = calloc(numitems,sizeof(struct huffitem));
        }
        return(bfp);
    }
    set_commpressionvars_fname(readonly,bfp->fname,coinstr,typestr,-1);
    bfp->fp = _open_varsfile(readonly,&bfp->blocknum,bfp->fname,coinstr);
    if ( bfp->fp != 0 != 0 ) // needs to be unique filtered, so use hashtable
    {
        if ( (bfp->mode & (BITSTREAM_STRING|BITSTREAM_HEXSTR)) != 0 )
            load_reference_strings(V,bfp,bfp->mode & BITSTREAM_HEXSTR);
        else if ( bfp->itemsize != 0 )
            load_fixed_fields(V,bfp);
        //else load_bitstream(V,bfp);
        bfp->blocknum = load_blockcheck(bfp->fp);
    }
    if (  refblock != 0xffffffff && bfp->blocknum != refblock )
    {
        printf("%s bfp->blocknum %u != refblock.%u mismatch FATAL if less than\n",typestr,bfp->blocknum,refblock);
        if ( bfp->blocknum < refblock )
            exit(-1);
    }
    //printf("%-8s mode.%d %s itemsize.%ld numitems.%d blocknum.%u refblock.%u\n",typestr,mode,coinstr,itemsize,bfp->ind,bfp->blocknum,refblock);
    return(bfp);
}

int32_t init_compressionvars(int32_t readonly,struct compressionvars *V,char *coinstr,int32_t maxblocknum)
{
    struct coin_info *cp = get_coin_info(coinstr);
    struct coinaddrinfo *addrp = 0;
    struct txinfo *tp = 0;
    struct scriptinfo *sp = 0;
    struct valueinfo *valp = 0;
    struct blockinfo *blockp = 0;
    uint32_t n=0,refblock;
    if ( V->rawbits == 0 )
    {
        strcpy(V->coinstr,coinstr);
        V->startmilli = milliseconds();
        if ( (V->maxblocknum= get_blockheight(cp)) == 0 )
            V->maxblocknum = maxblocknum;
        printf("init compression vars.%s: maxblocknum %d %d\n",coinstr,maxblocknum,get_blockheight(cp));
        V->disp = calloc(1,100000);
        V->buffer = calloc(1,100000);
        V->hp = hopen(V->buffer,100000);
        V->rawbits = calloc(1,100000);
        V->bfps[n] = init_bitstream_file(V,n,0,readonly,coinstr,"blocks",sizeof(*blockp),0xffffffff,0), n++;
        V->firstblock = refblock = V->bfps[0]->blocknum;
        V->valuebfp = n, V->bfps[n] = init_bitstream_file(V,n,BITSTREAM_UNIQUE|BITSTREAM_VALUE,readonly,coinstr,"values",sizeof(*valp),refblock,sizeof(uint64_t)), n++;
        V->inblockbfp = n, V->bfps[n] = init_bitstream_file(V,n,BITSTREAM_STATSONLY,readonly,coinstr,"inblock",sizeof(uint32_t),V->maxblocknum,0), n++;
        V->txinbfp = n, V->bfps[n] = init_bitstream_file(V,n,BITSTREAM_STATSONLY,readonly,coinstr,"intxind",sizeof(uint16_t),1<<16,0), n++;
        V->invoutbfp = n, V->bfps[n] = init_bitstream_file(V,n,BITSTREAM_STATSONLY,readonly,coinstr,"invout",sizeof(uint16_t),1<<16,0), n++;
        V->addrbfp = n, V->bfps[n] = init_bitstream_file(V,n,BITSTREAM_UNIQUE|BITSTREAM_STRING,readonly,coinstr,"addrs",sizeof(*addrp),refblock,sizeof(uint32_t)), n++;
        V->txidbfp = n, V->bfps[n] = init_bitstream_file(V,n,BITSTREAM_UNIQUE|BITSTREAM_HEXSTR,readonly,coinstr,"txids",sizeof(*tp),refblock,sizeof(uint32_t)), n++;
        V->scriptbfp = n, V->bfps[n] = init_bitstream_file(V,n,BITSTREAM_UNIQUE|BITSTREAM_HEXSTR|BITSTREAM_SCRIPT,readonly,coinstr,"scripts",sizeof(*sp),refblock,sizeof(uint32_t)), n++;
        V->voutsbfp = n, V->bfps[n] = init_bitstream_file(V,n,BITSTREAM_VOUTS,readonly,coinstr,"vouts",sizeof(struct rawblock_voutdata),refblock,0), n++;
        V->vinsbfp = n, V->bfps[n] = init_bitstream_file(V,n,BITSTREAM_VINS,readonly,coinstr,"vins",sizeof(struct address_entry),refblock,0), n++;
        V->bitstream = n, V->bfps[n] = init_bitstream_file(V,n,BITSTREAM_COMPRESSED,readonly,coinstr,"bitstream",0,refblock,0), n++;
        scan_ramchain(V);
    }
    if ( readonly != 0 )
        exit(1);
    return(n);
}

void clear_compressionvars(struct compressionvars *V,int32_t clearstats,int32_t frequi)
{
    V->maxitems = 0;
  /* int32_t i;
    struct scriptinfo *sp = 0;
    struct txinfo *tp = 0;
    struct coinaddrinfo *addrp = 0;
    struct valueinfo *valp = 0;
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
    }*/
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
    struct blockinfo B;
    long sum,sum2,fpos;
    uint32_t slice,i;
    memset(&B,0,sizeof(B));
    if ( prevblocknum != 0xffffffff )
    {
        B.firstvout = V->firstvout, B.firstvin = V->firstvin;
        append_to_streamfile(V->bfps[0],prevblocknum,&B,1,0);
        V->firstvout = V->bfps[V->voutsbfp]->ind;
        V->firstvin = V->bfps[V->vinsbfp]->ind;
        B.firstvout = V->firstvout, B.firstvin = V->firstvin;
        fpos = ftell(V->bfps[0]->fp);
        append_to_streamfile(V->bfps[0],prevblocknum,&B,1,1);
        fseek(V->bfps[0]->fp,fpos,SEEK_SET);
        sum = sum2 = fpos;
        for (i=1; i<V->numbfps; i++)
        {
            if ( V->bfps[i]->fp != 0 )
            {
                emit_blockcheck(V->bfps[i]->fp,prevblocknum);
                sum += ftell(V->bfps[i]->fp);
            }
        }
        sum2 += ftell(V->bfps[V->voutsbfp]->fp) + ftell(V->bfps[V->vinsbfp]->fp);
        // numhuffinds = emit_compressed_block(V,prevblocknum,frequi);
        if ( V->disp != 0 )
        {
            sprintf(V->disp+strlen(V->disp),"-> max.%-4d %.1f %.1f est %.1f minutes\n%s F.%d NEWBLOCK.%u | ",V->maxitems,(double)sum/(prevblocknum+1),(double)sum2/(prevblocknum+1),estimate_completion(V->coinstr,V->startmilli,V->processed,(int32_t)V->maxblocknum-prevblocknum)/60,V->coinstr,frequi,prevblocknum);
            printf("%s",V->disp);
            V->disp[0] = 0;
        }
        calc_frequi(&slice,V->coinstr,newblocknum);
        clear_compressionvars(V,(newblocknum % slice) == 0,frequi);
    }
    V->blocknum = newblocknum;
    V->processed++;
    return(newblocknum);
}

void set_rawblock_voutdata(struct rawblock_voutdata *v,uint32_t tp_ind,uint32_t vout,uint32_t addr_ind,uint64_t value,uint32_t sp_ind)
{
    memset(v,0,sizeof(*v));
    v->tp_ind = tp_ind;
    v->vout = vout;
    v->addr_ind = addr_ind;
    v->value = value;
    v->sp_ind = sp_ind;
}

void update_ramchain(struct compressionvars *V,char *coinstr,char *addr,struct address_entry *bp,uint64_t value,char *txidstr,char *script)
{
    char valuestr[128],mode;
    int32_t frequi,datalen,createdflag;
    uint8_t databuf[4096];
    struct rawblock_voutdata vout;
    struct coinaddrinfo *addrp = 0;
    struct txinfo *tp = 0;
    struct scriptinfo *sp = 0;
    struct valueinfo *valp = 0;
//printf("update ramchain.(%s) addr.(%s) block.%d vin.%d %p %p\n",coinstr,addr,bp->blocknum,bp->vinflag,txidstr,script);
    if ( V->numbfps != 0 )
    {
//printf("update compressionvars vinflag.%d\n",bp->vinflag);
        if ( bp->vinflag == 0 )
        {
            if (txidstr != 0 && script != 0 ) // txidstr != 0 && script != 0 && value != 0 &&
            {
//printf("txid.(%s) %s\n",txidstr,script);
                frequi = calc_frequi(0,V->coinstr,V->blocknum);
                if ( bp->blocknum != V->blocknum )
                    V->blocknum = flush_compressionvars(V,V->blocknum,bp->blocknum,frequi);
                addrp = update_bitstream_file(&createdflag,V->bfps[V->addrbfp],bp->blocknum,0,0,addr);
                datalen = (uint32_t)(strlen(txidstr) >> 1);
                decode_hex(databuf,datalen,txidstr);
                tp = update_bitstream_file(&createdflag,V->bfps[V->txidbfp],bp->blocknum,databuf,datalen,txidstr);
                if ( strlen(script) < 1024 )
                {
                    mode = calc_scriptmode(&datalen,databuf,script,1,addrp->item.huffind);
                    if ( (sp= update_bitstream_file(&createdflag,V->bfps[V->scriptbfp],bp->blocknum,databuf,datalen,script)) != 0 && createdflag != 0 )
                        sp->addrhuffind = addrp->item.huffind, sp->mode = mode;
                } else sp = 0;
                expand_nxt64bits(valuestr,value);
                if ( (valp= update_bitstream_file(&createdflag,V->bfps[V->valuebfp],bp->blocknum,&value,sizeof(value),valuestr)) != 0 && createdflag != 0 )
                    valp->value = value;
       //if ( 0 && V->disp != 0 )
                //    sprintf(V->disp+strlen(V->disp),"{A%d T%d.%d S%d %.8f} ",V->addrind,V->txind,bp->v,V->scriptind,dstr(value));
                if ( tp != 0 && addrp != 0 && sp != 0 )
                {
                    set_rawblock_voutdata(&vout,tp->item.huffind,bp->v,addrp->item.huffind,value,sp->item.huffind);
                    update_bitstream_file(&createdflag,V->bfps[V->voutsbfp],bp->blocknum,&vout,sizeof(vout),0);
                }
            }
            else
            {
                if ( 0 && V->disp != 0 )
                    sprintf(V->disp+strlen(V->disp),"[%d %d %d] ",bp->blocknum,bp->txind,bp->v);
                update_vinsbfp(V,V->bfps[V->vinsbfp],bp,V->blocknum);
            }
            V->maxitems++;
        }
        else
        {
            // vin txid:vin is dereferenced above
            //sprintf(V->disp+strlen(V->disp),"(%d %d %d) ",bp->blocknum,bp->txind,bp->v);
        }
        //if ( IS_LIBTEST != 7 )
        //    fclose(V->fp);
    }
}

int main(int argc,const char *argv[])
{
    FILE *fp;
    cJSON *json = 0;
    int32_t retval;
    char ipaddr[64],*oldport,*newport,portstr[64],*retstr;
#ifdef __APPLE__
#else
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
