//
//  coins777.c
//  crypto777
//
//  Created by James on 4/9/15.
//  Copyright (c) 2015 jl777. All rights reserved.
//
// code goes so fast, might need to change /proc/sys/net/ipv4/tcp_tw_recycle to have a 1 in it
//

#ifdef DEFINES_ONLY
#ifndef crypto777_coins777_h
#define crypto777_coins777_h
#include <stdio.h>
#include "uthash.h"
#include "cJSON.h"
#include "huffstream.c"
#include "system777.c"
#include "storage.c"
#include "db777.c"
#include "files777.c"
#include "utils777.c"
#include "gen1pub.c"

#define OP_RETURN_OPCODE 0x6a
#define RAMCHAIN_PTRSBUNDLE 4096

#define MAX_BLOCKTX 0xffff
struct rawvin { char txidstr[128]; uint16_t vout; };
struct rawvout { char coinaddr[128],script[2048]; uint64_t value; };
struct rawtx { uint16_t firstvin,numvins,firstvout,numvouts; char txidstr[128]; };

struct rawblock
{
    uint32_t blocknum,timestamp;
    uint16_t numtx,numrawvins,numrawvouts,pad;
    uint64_t minted;
    char blockhash[65],merkleroot[65];
    struct rawtx txspace[MAX_BLOCKTX];
    struct rawvin vinspace[MAX_BLOCKTX];
    struct rawvout voutspace[MAX_BLOCKTX];
};

struct packedvin { uint32_t txidstroffset; uint16_t vout; };
struct packedvout { uint32_t coinaddroffset,scriptoffset; uint64_t value; };
struct packedtx { uint16_t firstvin,numvins,firstvout,numvouts; uint32_t txidstroffset; };

struct packedblock
{
    uint16_t crc16,numtx,numrawvins,numrawvouts;
    uint64_t minted;
    uint32_t blocknum,timestamp,blockhash_offset,merkleroot_offset,txspace_offsets,vinspace_offsets,voutspace_offsets,allocsize;
    uint8_t rawdata[];
};

#define MAX_COINTX_INPUTS 16
#define MAX_COINTX_OUTPUTS 8
struct cointx_input { struct rawvin tx; char coinaddr[64],sigs[1024]; uint64_t value; uint32_t sequence; char used; };
struct cointx_info
{
    uint32_t crc; // MUST be first
    char coinstr[16];
    uint64_t inputsum,amount,change,redeemtxid;
    uint32_t allocsize,batchsize,batchcrc,gatewayid,isallocated;
    // bitcoin tx order
    uint32_t version,timestamp,numinputs;
    uint32_t numoutputs;
    struct cointx_input inputs[MAX_COINTX_INPUTS];
    struct rawvout outputs[MAX_COINTX_OUTPUTS];
    uint32_t nlocktime;
    // end bitcoin txcalc_nxt64bits
    char signedtx[];
};

struct sha256_state
{
    uint64_t length;
    uint32_t state[8],curlen;
    uint8_t buf[64];
};

struct upair32 { uint32_t firstvout,firstvin; };
struct unspentmap { uint64_t value; uint32_t ind,scriptind; };
struct ledger_addrinfo { uint64_t balance; uint32_t firstblocknum,count:28,notify:1,pending:1,MGW:1,dirty:1; struct unspentmap unspents[]; };

struct ledger_state
{
    char name[16];
    uint8_t sha256[256 >> 3];
    struct sha256_state state;
    struct db777 *DB;
    FILE *fp;
    int32_t ind,allocsize;
};

struct ledger_info
{
    struct env777 DBs;
    uint64_t voutsum,spendsum,addrsum,totalsize;
    double startmilli,load_elapsed,calc_elapsed;
    uint32_t blocknum,blockpending,numsyncs,sessionid,counter,startblocknum,endblocknum,syncfreq,needbackup;
    struct ledger_state ledger,revaddrs,addrs,packed,revtxids,txids,scripts,revscripts,blocks,unspentmap,txoffsets,spentbits,addrinfos;
    //uint8_t sha256[256 >> 3];
    //struct sha256_state ledgerstate;
    uint8_t getbuf[1000000];
};

struct ramchain
{
    char name[16];
    char serverport[512],userpass[4096];
    double lastgetinfo;
    uint32_t RTblocknum,readyflag,syncflag,paused,minconfirms;
    struct rawblock *EMIT,*DECODE;
    struct ledger_info *activeledger;//,*session_ledgers[1 << CONNECTION_NUMBITS];
};

struct packed_info
{
    struct rawblock *EMIT,*DECODE;
    uint32_t packedstart,packedend,packedincr,RTblocknum,packedblocknum,maxpackedblocks,readahead;
    struct packedblock **packed;
};

struct coin777_state
{
    char name[16];
    uint8_t sha256[256 >> 3];
    struct sha256_state state;
    struct db777 *DB;
    struct mappedptr M;
    struct alloc_space MEM;
    queue_t writeQ; portable_mutex_t mutex;
    void *table;
    uint32_t maxitems,itemsize,flags;
};

struct coin777_hashes { uint64_t ledgerhash,credits,debits; uint8_t sha256[12][256 >> 3]; struct sha256_state states[12]; uint32_t blocknum,numsyncs,timestamp,txidind,unspentind,numspends,addrind,scriptind; };
struct coin_offsets { bits256 blockhash,merkleroot; uint64_t credits,debits; uint32_t timestamp,txidind,unspentind,numspends,addrind,scriptind; uint8_t check[16]; };
struct unspent_info { uint64_t value; uint32_t addrind,spending_txidind; uint16_t spending_vin; };
struct hashed_uint32 { UT_hash_handle hh; uint32_t ind; };

#ifndef ADDRINFO_SIZE
#define ADDRINFO_SIZE 168
#endif

struct coin777_addrinfo
{
    int64_t balance,syncbalance;
    uint32_t firstblocknum,num,syncnum;
    int16_t scriptlen,unspents_offset;
    uint8_t addrlen; uint8_t notify:1,pending:1,MGW:1,dirty:1,tbd:4;
    char coinaddr[ADDRINFO_SIZE - 34];
};

#define COIN777_SHA256 256

struct coin777
{
    char name[16],serverport[64],userpass[128],*jsonstr;
    cJSON *argjson;
    double lastgetinfo;
    struct ramchain ramchain;
    int32_t use_addmultisig,minconfirms;
    struct packed_info P;
    
    uint64_t minted,addrsum; double calc_elapsed,startmilli;
    uint32_t latestblocknum,blocknum,numsyncs,RTblocknum,startblocknum,endblocknum,needbackup,num,syncfreq;
    struct coin_offsets latest; long totalsize;
    struct env777 DBs;  struct coin777_state *sps[16],txidDB,addrDB,scriptDB,ledger,blocks,txoffsets,txidbits,unspents,spends,addrinfos,activeDB,hashDB;
    struct alloc_space tmpMEM;
};

char *bitcoind_RPC(char **retstrp,char *debugstr,char *url,char *userpass,char *command,char *params);
char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params);
struct coin777 *coin777_create(char *coinstr,cJSON *argjson);
int32_t coin777_close(char *coinstr);
struct coin777 *coin777_find(char *coinstr,int32_t autocreate);
int32_t rawblock_load(struct rawblock *raw,char *coinstr,char *serverport,char *userpass,uint32_t blocknum);
void rawblock_patch(struct rawblock *raw);

void update_sha256(unsigned char hash[256 >> 3],struct sha256_state *state,unsigned char *src,int32_t len);
struct db777 *db777_open(int32_t dispflag,struct env777 *DBs,char *name,char *compression,int32_t flags,int32_t valuesize);
void ram_clear_rawblock(struct rawblock *raw,int32_t totalflag);
void coin777_disprawblock(struct rawblock *raw);

int32_t coin777_parse(struct coin777 *coin,uint32_t RTblocknum,int32_t syncflag,int32_t minconfirms);
void coin777_initDBenv(struct coin777 *coin);
uint32_t coin777_startblocknum(struct coin777 *coin,uint32_t synci);
int32_t coin777_getinds(void *state,uint32_t blocknum,uint64_t *creditsp,uint64_t *debitsp,uint32_t *timestampp,uint32_t *txidindp,uint32_t *unspentindp,uint32_t *numspendsp,uint32_t *addrindp,uint32_t *scriptindp);
int32_t coin777_initmmap(struct coin777 *coin,uint32_t blocknum,uint32_t txidind,uint32_t addrind,uint32_t scriptind,uint32_t unspentind,uint32_t totalspends);
int32_t coin777_syncblocks(struct coin777_hashes *inds,int32_t max,struct coin777 *coin);
uint64_t coin777_ledgerhash(char *ledgerhash,struct coin777_hashes *H);
int32_t coin777_txidstr(struct coin777 *coin,char *txidstr,int32_t max,uint32_t txidind,uint32_t addrind);
int32_t coin777_scriptstr(struct coin777 *coin,char *scriptstr,int32_t max,uint32_t scriptind,uint32_t addrind);
int32_t coin777_coinaddr(struct coin777 *coin,char *coinaddr,int32_t max,uint32_t addrind,uint32_t addrind2);
uint32_t coin777_txidind(uint32_t *firstblocknump,struct coin777 *coin,char *txidstr);
uint32_t coin777_addrind(uint32_t *firstblocknump,struct coin777 *coin,char *coinaddr);
uint32_t coin777_scriptind(uint32_t *firstblocknump,struct coin777 *coin,char *coinaddr,char *scriptstr);
uint32_t coin777_addrtx(struct coin777 *coin,uint32_t *blocknump,uint32_t addrtx[2][2],struct coin777_addrinfo *A,uint32_t addrind,int32_t addrtxi);
int32_t coin777_replayblocks(struct coin777 *coin,uint32_t startblocknum,uint32_t endblocknum,int32_t verifyflag);

#endif
#else
#ifndef crypto777_coins777_c
#define crypto777_coins777_c

#ifndef crypto777_coins777_h
#define DEFINES_ONLY
#include "coins777.c"
#endif

void debugstop()
{
    //#ifdef __APPLE__
    while ( 1 )
        sleep(60);
    //#endif
}

// coin777 parse funcs
uint64_t parse_voutsobj(int32_t (*voutfuncp)(void *state,uint64_t *creditsp,uint32_t txidind,uint16_t vout,uint32_t unspentind,char *coinaddr,char *script,uint64_t value,uint32_t *addrindp,uint32_t *scriptindp,uint32_t blocknum),void *state,uint64_t *creditsp,uint32_t txidind,uint32_t *firstvoutp,uint16_t *txnumvoutsp,uint32_t *numrawvoutsp,uint32_t *addrindp,uint32_t *scriptindp,cJSON *voutsobj,uint32_t blocknum)
{
    char coinaddr[8192],script[8192]; cJSON *item; uint64_t value,total = 0; int32_t i,numvouts = 0;
    *firstvoutp = (*numrawvoutsp);
    if ( voutsobj != 0 && is_cJSON_Array(voutsobj) != 0 && (numvouts= cJSON_GetArraySize(voutsobj)) > 0 )
    {
        (*txnumvoutsp) = numvouts;
        for (i=0; i<numvouts; i++,(*numrawvoutsp)++)
        {
            item = cJSON_GetArrayItem(voutsobj,i);
            value = conv_cJSON_float(item,"value");
            total += value;
            _extract_txvals(coinaddr,script,1,item); // default to nohexout
            if ( (*voutfuncp)(state,creditsp,txidind,i,(*numrawvoutsp),coinaddr,script,value,addrindp,scriptindp,blocknum) != 0 )
                printf("error vout.%d numrawvouts.%u\n",i,(*numrawvoutsp));
        }
    } else (*txnumvoutsp) = 0, printf("error with vouts\n");
    return(total);
}

uint64_t parse_vinsobj(uint64_t (*vinfuncp)(void *state,uint64_t *debitsp,uint32_t txidind,uint16_t vin,uint32_t totalspends,char *spendtxidstr,uint16_t spendvout,uint32_t blocknum),void *state,uint64_t *debitsp,uint32_t txidind,uint32_t *firstvinp,uint16_t *txnumvinsp,uint32_t *numrawvinsp,cJSON *vinsobj,uint32_t blocknum)
{
    char txidstr[8192],coinbase[8192]; cJSON *item; int32_t i,numvins = 0; uint64_t value,total = 0;
    *firstvinp = (*numrawvinsp);
    if ( vinsobj != 0 && is_cJSON_Array(vinsobj) != 0 && (numvins= cJSON_GetArraySize(vinsobj)) > 0 )
    {
        (*txnumvinsp) = numvins;
        for (i=0; i<numvins; i++,(*numrawvinsp)++)
        {
            item = cJSON_GetArrayItem(vinsobj,i);
            if ( numvins == 1  )
            {
                copy_cJSON(coinbase,cJSON_GetObjectItem(item,"coinbase"));
                if ( strlen(coinbase) > 1 )
                {
                    (*txnumvinsp) = 0;
                    return(0);
                }
            }
            copy_cJSON(txidstr,cJSON_GetObjectItem(item,"txid"));
            if ( (value= (*vinfuncp)(state,debitsp,txidind,i,(*numrawvinsp),txidstr,(int)get_cJSON_int(item,"vout"),blocknum)) == 0 )
                printf("error vin.%d numrawvins.%u\n",i,(*numrawvinsp));
            total += value;
        }
    } else (*txnumvinsp) = 0, printf("error with vins\n");
    return(total);
}

int32_t parse_block(void *state,uint64_t *creditsp,uint64_t *debitsp,uint32_t *txidindp,uint32_t *numrawvoutsp,uint32_t *numrawvinsp,uint32_t *addrindp,uint32_t *scriptindp,char *coinstr,char *serverport,char *userpass,uint32_t blocknum,
    int32_t (*blockfuncp)(void *state,uint32_t blocknum,char *blockhash,char *merkleroot,uint32_t timestamp,uint64_t minted,uint32_t txidind,uint32_t unspentind,uint32_t numspends,uint32_t addrind,uint32_t scriptind,uint64_t credits,uint64_t debits),
    uint64_t (*vinfuncp)(void *state,uint64_t *debitsp,uint32_t txidind,uint16_t vin,uint32_t totalspends,char *spendtxidstr,uint16_t spendvout,uint32_t blocknum),
    int32_t (*voutfuncp)(void *state,uint64_t *creditsp,uint32_t txidind,uint16_t vout,uint32_t unspentind,char *coinaddr,char *script,uint64_t value,uint32_t *addrindp,uint32_t *scriptindp,uint32_t blocknum),
    int32_t (*txfuncp)(void *state,uint32_t blocknum,uint32_t txidind,char *txidstr,uint32_t firstvout,uint16_t numvouts,uint64_t total,uint32_t firstvin,uint16_t numvins))
{
    char blockhash[8192],merkleroot[8192],txidstr[8192],mintedstr[8192],*txidjsonstr; cJSON *json,*txarray,*txjson;
    uint32_t checkblocknum,timestamp,firstvout,firstvin; uint16_t numvins,numvouts; int32_t txind,numtx = 0; uint64_t minted,total=0,spent=0;
    minted = total = 0;
    if ( (json= _get_blockjson(0,coinstr,serverport,userpass,0,blocknum)) != 0 )
    {
        if ( get_API_int(cJSON_GetObjectItem(json,"height"),0) == blocknum )
        {
            copy_cJSON(blockhash,cJSON_GetObjectItem(json,"hash"));
            copy_cJSON(merkleroot,cJSON_GetObjectItem(json,"merkleroot"));
            timestamp = (uint32_t)get_cJSON_int(cJSON_GetObjectItem(json,"time"),0);
            copy_cJSON(mintedstr,cJSON_GetObjectItem(json,"mint"));
            if ( mintedstr[0] == 0 )
                copy_cJSON(mintedstr,cJSON_GetObjectItem(json,"newmint"));
            if ( mintedstr[0] != 0 )
                minted = (uint64_t)(atof(mintedstr) * SATOSHIDEN);
            if ( (txarray= _rawblock_txarray(&checkblocknum,&numtx,json)) != 0 && checkblocknum == blocknum )
            {
                if ( (*blockfuncp)(state,blocknum,blockhash,merkleroot,timestamp,minted,(*txidindp),(*numrawvoutsp),(*numrawvinsp),(*addrindp),(*scriptindp),(*creditsp),(*debitsp)) != 0 )
                    printf("error adding blocknum.%u\n",blocknum);
                firstvout = (*numrawvoutsp), firstvin = (*numrawvinsp);
                numvouts = numvins = 0;
                for (txind=0; txind<numtx; txind++,(*txidindp)++)
                {
                    copy_cJSON(txidstr,cJSON_GetArrayItem(txarray,txind));
                    if ( (txidjsonstr= _get_transaction(coinstr,serverport,userpass,txidstr)) != 0 )
                    {
                        if ( (txjson= cJSON_Parse(txidjsonstr)) != 0 )
                        {
                            total += parse_voutsobj(voutfuncp,state,creditsp,(*txidindp),&firstvout,&numvouts,numrawvoutsp,addrindp,scriptindp,cJSON_GetObjectItem(txjson,"vout"),blocknum);
                            spent += parse_vinsobj(vinfuncp,state,debitsp,(*txidindp),&firstvin,&numvins,numrawvinsp,cJSON_GetObjectItem(txjson,"vin"),blocknum);
                            free_json(txjson);
                        } else printf("update_txid_infos parse error.(%s)\n",txidjsonstr);
                        free(txidjsonstr);
                    }
                    else if ( blocknum != 0 )
                        printf("error getting.(%s) blocknum.%d\n",txidstr,blocknum);
                    if ( (*txfuncp)(state,blocknum,(*txidindp),txidstr,firstvout,numvouts,total,firstvin,numvins) != 0 )
                        printf("error adding txidind.%u blocknum.%u txind.%d\n",(*txidindp),blocknum,txind);
                }
                if ( (*blockfuncp)(state,blocknum+1,0,0,0,0,(*txidindp),(*numrawvoutsp),(*numrawvinsp),(*addrindp),(*scriptindp),(*creditsp),(*debitsp)) != 0 )
                    printf("error finishing blocknum.%u\n",blocknum);
            } else printf("error _get_blocktxarray for block.%d got %d n.%d\n",blocknum,checkblocknum,numtx);
        } else printf("blocknum.%u mismatched with %u\n",blocknum,get_API_int(cJSON_GetObjectItem(json,"height"),0));
        free_json(json);
    } else printf("get_blockjson error parsing.(%s)\n",txidstr);
    if ( Debuglevel > 2 )
        printf("BLOCK.%d: numtx.%d minted %.8f rawnumvins.%d rawnumvouts.%d\n",blocknum,numtx,dstr(minted),(*numrawvinsp),(*numrawvoutsp));
    return(numtx);
}

// coin777 DB funcs
void *coin777_getDB(void *dest,int32_t *lenp,void *transactions,struct db777 *DB,void *key,int32_t keylen)
{
    void *obj,*value,*result = 0;
    if ( (obj= sp_object(DB->db)) != 0 )
    {
        if ( sp_set(obj,"key",key,keylen) == 0 )
        {
            if ( (result= sp_get(transactions != 0 ? transactions : DB->db,obj)) != 0 )
            {
                value = sp_get(result,"value",lenp);
                memcpy(dest,value,*lenp);
                sp_destroy(result);
                return(dest);
            } //else printf("DB.%p %s no result transactions.%p key.%x\n",DB,DB->name,transactions,*(int *)key);
        } else printf("no key\n");
    } else printf("getDB no obj\n");
    return(0);
}

int32_t coin777_addDB(struct coin777 *coin,void *transactions,struct db777 *DB,void *key,int32_t keylen,void *value,int32_t valuelen)
{
    void *db,*obj; int32_t retval; extern int32_t Added;
    db = DB->asyncdb != 0 ? DB->asyncdb : DB->db;
    if ( (obj= sp_object(db)) == 0 )
        retval = -3;
    if ( sp_set(obj,"key",key,keylen) != 0 || sp_set(obj,"value",value,valuelen) != 0 )
    {
        sp_destroy(obj);
        printf("error setting key/value %s[%d]\n",DB->name,*(int *)key);
        retval = -4;
    }
    else
    {
        Added++;
        coin->totalsize += valuelen;
        retval = sp_set((transactions != 0 ? transactions : db),obj);
        if ( 0 && valuelen < 8192 )
        {
            void *check; char dest[8192]; int32_t len = sizeof(dest);
            check = coin777_getDB(dest,&len,transactions,DB,key,keylen);
            if ( check == 0 )
                printf("cant find just added key.%x\n",*(int *)key);
            else if ( memcmp(dest,value,valuelen) != 0 && len == valuelen )
                printf("cmp error just added key.%x len.%d valuelen.%d\n",*(int *)key,len,valuelen);
            //else printf("cmp success!\n");
        }
    }
    return(retval);
}

int32_t coin777_queueDB(struct coin777 *coin,struct db777 *DB,void *key,int32_t keylen,void *value,int32_t valuelen)
{
    //addritem = tmpalloc(coin->name,&coin->tmpMEM,sizeof(*addritem) + len + 1), addritem->addrind = addrind, strcpy(addritem->coinaddr,coinaddr);
    //queue_enqueue(DB->name,&coin->actives.writeQ,&actives->DL);
    return(coin777_addDB(coin,coin->DBs.transactions,DB,key,keylen,value,valuelen));
}

// coin777 MM funcs
void *coin777_ensure(struct coin777 *coin,struct coin777_state *sp,uint32_t ind)
{
    char fname[1024]; long needed,prevsize = 0; int32_t rwflag = 1;
    needed = (ind + 2) * sp->itemsize;
    if ( needed > sp->M.allocsize )
    {
        db777_path(fname,coin->name,"",0), strcat(fname,"/"), strcat(fname,sp->name), os_compatible_path(fname);
        needed += 65536 * sp->itemsize;
        printf("REMAP.%s %llu -> %ld [%ld] (%s)\n",sp->name,(long long)sp->M.allocsize,needed,(long)(needed - sp->M.allocsize)/sp->itemsize,fname);
        if ( sp->M.fileptr != 0 )
        {
            sync_mappedptr(&sp->M,0);
            release_map_file(sp->M.fileptr,sp->M.allocsize);
            sp->M.fileptr = 0, prevsize = sp->M.allocsize;
            sp->M.allocsize = 0;
        }
        needed = ensure_filesize(fname,needed,0);
    }
    if ( sp->M.fileptr == 0 )
    {
        if ( init_mappedptr(&sp->MEM.ptr,&sp->M,0,rwflag,fname) != 0 )
        {
            sp->MEM.size = sp->M.allocsize;
            sp->maxitems = (uint32_t)(sp->MEM.size / sp->itemsize);
            if ( prevsize != 0 )
                memset((void *)((long)sp->M.fileptr + prevsize),0,(sp->MEM.size - prevsize));
            printf("%p %s maxitems.%u (MEMsize.%ld / itemsize.%d) prevsize.%ld needed.%ld\n",sp->MEM.ptr,sp->name,sp->maxitems,sp->MEM.size,sp->itemsize,prevsize,needed);
        }
    }
    if ( (sp->table= sp->M.fileptr) == 0 )
        printf("couldnt map %s\n",fname);
    return(sp->table);
}

void *coin777_itemptr(struct coin777 *coin,struct coin777_state *sp,uint32_t ind)
{
    void *ptr = sp->table;
    if ( ptr == 0 || ind >= sp->maxitems )
    {
        sp->table = coin777_ensure(coin,sp,ind);
        if ( (ptr= sp->table) == 0 )
        {
            printf("SECOND ERROR %s overflow? %p addrind.%u vs max.%u\n",sp->name,ptr,ind,sp->maxitems);
            return(0);
        }
    }
    ptr = (void *)((long)ptr + sp->itemsize*ind);
    return(ptr);
}

int32_t coin777_RWmmap(int32_t writeflag,void *value,struct coin777 *coin,struct coin777_state *sp,uint32_t rawind)
{
    static uint8_t zeroes[4096];
    void *ptr; int32_t i,size,retval = 0;
    if ( (writeflag & COIN777_SHA256) != 0 )
    {
        coin->totalsize += sp->itemsize;
        update_sha256(sp->sha256,&sp->state,value,sp->itemsize);
    }
    if ( sp->DB != 0 )
    {
        printf("unexpected DB path in coin777_RWmmap %s\n",sp->name);
        if ( writeflag != 0 )
            return(coin777_addDB(coin,coin->DBs.transactions,sp->DB,&rawind,sizeof(rawind),value,sp->itemsize));
        else
        {
            size = sp->itemsize;
            if ( (ptr= coin777_getDB(value,&size,coin->DBs.transactions,sp->DB,&rawind,sizeof(rawind))) == 0 || size != sp->itemsize )
                return(-1);
            return(0);
        }
    }
    else
    {
        portable_mutex_lock(&sp->mutex);
        if ( (ptr= coin777_itemptr(coin,sp,rawind)) != 0 )
        {
            if ( writeflag != 0 )
            {
                if ( memcmp(value,ptr,sp->itemsize) != 0 )
                {
                    if ( (sp->flags & DB777_VOLATILE) == 0 )
                    {
                        if ( sp->itemsize <= sizeof(zeroes) )
                        {
                            if ( memcmp(ptr,zeroes,sp->itemsize) != 0 )
                            {
                                for (i=0; i<sp->itemsize; i++)
                                    printf("%02x ",((uint8_t *)ptr)[i]);
                                printf("existing.%s %d <-- overwritten\n",sp->name,sp->itemsize);
                                for (i=0; i<sp->itemsize; i++)
                                    printf("%02x ",((uint8_t *)value)[i]);
                                printf("new value.%s %d rawind.%u\n",sp->name,sp->itemsize,rawind);
                            }
                        } else printf("coin777_RWmmap unexpected itemsize.%d for %s bigger than %ld\n",sp->itemsize,sp->name,sizeof(zeroes));
                    }
                    memcpy(ptr,value,sp->itemsize);
                }
            }
            else memcpy(value,ptr,sp->itemsize);
        } else retval = -2;
        portable_mutex_unlock(&sp->mutex);
    }
    return(retval);
}

// coin777 lookup funcs
void coin777_addind(struct coin777 *coin,struct coin777_state *sp,void *key,int32_t keylen,uint32_t ind)
{
    struct hashed_uint32 *entry,*table; void *ptr;
    ptr = tmpalloc(coin->name,&coin->tmpMEM,keylen), memcpy(ptr,key,keylen);
    entry = tmpalloc(coin->name,&coin->tmpMEM,sizeof(*entry)), entry->ind = ind;
    table = sp->table; HASH_ADD_KEYPTR(hh,table,ptr,keylen,entry); sp->table = table;
}

uint32_t coin777_findind(struct coin777 *coin,struct coin777_state *sp,uint8_t *data,int32_t datalen)
{
    struct hashed_uint32 *entry; extern int32_t Duplicate;
    if ( RAMCHAINS.fastmode != 0 )
    {
        HASH_FIND(hh,(struct hashed_uint32 *)sp->table,data,datalen,entry);
        if ( entry != 0 )
        {
            Duplicate++;
            return(entry->ind);
        }
    }
    return(0);
}

uint32_t coin777_txidind(uint32_t *firstblocknump,struct coin777 *coin,char *txidstr)
{
    bits256 txid; uint32_t txidind = 0; int32_t tmp = sizeof(txidind);
    *firstblocknump = 0;
    memset(txid.bytes,0,sizeof(txid)), decode_hex(txid.bytes,sizeof(txid),txidstr);
    if ( (txidind= coin777_findind(coin,&coin->txidDB,txid.bytes,sizeof(txid))) == 0 )
        coin777_getDB(&txidind,&tmp,coin->DBs.transactions,coin->txidDB.DB,txid.bytes,sizeof(txid));
    return(txidind);
}

uint32_t coin777_addrind(uint32_t *firstblocknump,struct coin777 *coin,char *coinaddr)
{
    uint32_t addrind; int32_t len,tmp = sizeof(addrind);
    *firstblocknump = 0;
    len = (int32_t)strlen(coinaddr) + 1;
    if ( (addrind= coin777_findind(coin,&coin->addrDB,(uint8_t *)coinaddr,len)) == 0 )
        coin777_getDB(&addrind,&tmp,coin->DBs.transactions,coin->addrDB.DB,coinaddr,len);
    return(addrind);
}

int32_t coin777_script0(struct coin777 *coin,uint32_t addrind,uint8_t *script,int32_t scriptlen)
{
    struct coin777_addrinfo A;
    if ( coin777_RWmmap(0,&A,coin,&coin->addrinfos,addrind) == 0 && A.scriptlen == scriptlen )
        return(memcmp(script,&A.coinaddr[A.addrlen],scriptlen) == 0);
    return(0);
}

uint32_t coin777_scriptind(uint32_t *firstblocknump,struct coin777 *coin,char *coinaddr,char *scriptstr)
{
    uint8_t script[4096]; uint32_t addrind,scriptind; int32_t scriptlen,tmp = sizeof(scriptind);
    *firstblocknump = 0;
    scriptlen = (int32_t)strlen(scriptstr) >> 1, decode_hex(script,scriptlen,scriptstr);
    if ( (addrind= coin777_addrind(firstblocknump,coin,coinaddr)) != 0 && coin777_script0(coin,addrind,script,scriptlen) != 0 )
        return(0);
    if ( (scriptind= coin777_findind(coin,&coin->scriptDB,script,scriptlen)) == 0 )
        coin777_getDB(&scriptind,&tmp,coin->DBs.transactions,coin->scriptDB.DB,script,scriptlen);
    if ( scriptind == 0 )
        return(0xffffffff);
    return(scriptind);
}

int32_t coin777_txidstr(struct coin777 *coin,char *txidstr,int32_t max,uint32_t txidind,uint32_t addrind)
{
    bits256 txid;
    if ( coin777_RWmmap(0,&txid,coin,&coin->txidbits,txidind) == 0 )
        init_hexbytes_noT(txidstr,txid.bytes,sizeof(txid));
    return(0);
}

uint64_t coin777_value(struct coin777 *coin,uint32_t *unspentindp,struct unspent_info *U,uint32_t txidind,int16_t vout)
{
    uint32_t unspentind,txoffsets[2];
    if ( coin777_RWmmap(0,txoffsets,coin,&coin->txoffsets,txidind) == 0  )
    {
        (*unspentindp) = unspentind = txoffsets[0] + vout;
        if ( coin777_RWmmap(0,U,coin,&coin->unspents,unspentind) == 0 )
            return(U->value);
        else printf("error getting unspents[%u]\n",unspentind);
    } else printf("error getting txoffsets for txidind.%u\n",txidind);
    return(0);
}

// coin777 addrinfo funcs
#define coin777_scriptptr(A) ((A)->scriptlen == 0 ? 0 : (uint8_t *)&(A)->coinaddr[(A)->addrlen])
#define coin777_maxfixed(A) (((A)->unspents_offset == 0 || (A)->unspents_offset == sizeof((A)->coinaddr)) ? 0 : (int32_t)((sizeof((A)->coinaddr) - (A)->unspents_offset) / (2 * sizeof(uint32_t))))
#define coin777_unspents(A) (coin777_maxfixed(A) <= 0 ? 0 : (uint32_t *)&(A)->coinaddr[(A)->unspents_offset])

int32_t coin777_scriptstr(struct coin777 *coin,char *scriptstr,int32_t max,uint32_t scriptind,uint32_t addrind)
{
    struct coin777_addrinfo A; uint8_t *scriptptr;
    if ( scriptind != 0 )
    {
        printf("need to reverse scriptind.%u\n",scriptind);
        //if ( (ptr= coin777_getDB(&scriptind,&tmp,coin->DBs.transactions,coin->scripts.DB,script,scriptlen)) == 0 || scriptind == 0 || tmp != sizeof(*ptr) )
        //    init_hexbytes_noT(scriptstr,script,sizeof(txid));
    }
    else
    {
        memset(&A,0,sizeof(A));
        if ( coin777_RWmmap(0,&A,coin,&coin->addrinfos,addrind) == 0 && (scriptptr= coin777_scriptptr(&A)) != 0 )
            init_hexbytes_noT(scriptstr,scriptptr,A.scriptlen);
    }
    return(0);
}

int32_t coin777_coinaddr(struct coin777 *coin,char *coinaddr,int32_t max,uint32_t addrind,uint32_t addrind2)
{
    struct coin777_addrinfo A;
    memset(&A,0,sizeof(A));
    if ( coin777_RWmmap(0,&A,coin,&coin->addrinfos,addrind) == 0 )
        strcpy(coinaddr,A.coinaddr);
    return(-1);
}

int32_t coin777_activebuf(uint8_t *buf,int64_t value,uint32_t addrind,uint32_t blocknum)
{
    int32_t buflen = 0;
    memcpy(&buf[buflen],&value,sizeof(value)), buflen += sizeof(value);
    memcpy(&buf[buflen],&addrind,sizeof(addrind)), buflen += sizeof(addrind);
    memcpy(&buf[buflen],&blocknum,sizeof(blocknum)), buflen += sizeof(blocknum);
    return(buflen);
}

int32_t coin777_update_addrinfo(struct coin777 *coin,uint32_t addrind,uint32_t unspentind,int64_t value,uint32_t blocknum)
{
    struct coin777_addrinfo A; uint32_t addrtx[2][2],tmp[2],*unspents; uint64_t lbalance; int32_t maxfixed,buflen; uint8_t buf[32];
    memset(&A,0,sizeof(A));
    if ( coin777_RWmmap(0,&A,coin,&coin->addrinfos,addrind) == 0 )
    {
        coin777_RWmmap(0,&lbalance,coin,&coin->ledger,addrind);
        if ( lbalance != A.balance )
            printf("coin777_update_addrinfo: block.%u addrind.%u num.%d ledger %.8f vs %.8f? new value %.8f\n",blocknum,addrind,A.num,dstr(lbalance),dstr(A.balance),dstr(value));
        A.balance += value;
        coin777_RWmmap(1,&A.balance,coin,&coin->ledger,addrind);
        maxfixed = coin777_maxfixed(&A);
        if ( Debuglevel > 2 )
            printf("addrind.%u num.%d maxfixed.%d %s += %.8f -> %.8f\n",addrind,A.num,maxfixed,A.coinaddr,dstr(value),dstr(A.balance));
        if ( maxfixed > 0 && A.num < maxfixed && (unspents= coin777_unspents(&A)) != 0 )
        {
            unspents[A.num << 1] = unspentind, unspents[(A.num << 1) + 1] = blocknum;
            addrtx[1][0] = unspentind, addrtx[1][1] = blocknum;
        }
        else
        {
            //printf("store.%d (u%d b%d) -> addrind.%d\n",A.num,unspentind,blocknum,addrind);
            addrtx[0][0] = addrind, addrtx[0][1] = A.num;
            addrtx[1][0] = unspentind, addrtx[1][1] = blocknum;
            coin777_queueDB(coin,coin->activeDB.DB,addrtx[0],sizeof(addrtx[0]),addrtx[1],sizeof(addrtx[1]));
        }
        A.num++;
        buflen = coin777_activebuf(buf,value,addrind,blocknum);
        update_sha256(coin->ledger.sha256,&coin->ledger.state,buf,buflen);
        tmp[0] = addrind, tmp[1] = unspentind, update_sha256(coin->activeDB.sha256,&coin->activeDB.state,buf,buflen);
        return(coin777_RWmmap(1,&A,coin,&coin->addrinfos,addrind));
    } else printf("coin777_unspent cant find addrinfo for addrind.%u\n",addrind);
    return(-1);
}

uint32_t coin777_addrtx(struct coin777 *coin,uint32_t *blocknump,uint32_t addrtx[2][2],struct coin777_addrinfo *A,uint32_t addrind,int32_t addrtxi)
{
    uint32_t *unspents,*ptr,unspentind = 0; int32_t len,maxfixed;
    maxfixed = coin777_maxfixed(A);
    if ( addrtxi < maxfixed && (unspents= coin777_unspents(A)) != 0 )
        addrtx[1][0] = unspentind = unspents[addrtxi << 1], addrtx[1][1] = *blocknump = unspents[(addrtxi << 1) + 1];
    else
    {
        len = sizeof(addrtx[1]), addrtx[0][0] = addrind, addrtx[0][1] = addrtxi;
        if ( (ptr= coin777_getDB(addrtx[1],&len,coin->DBs.transactions,coin->activeDB.DB,addrtx[0],sizeof(addrtx[0]))) != 0 )
            unspentind = addrtx[1][0], *blocknump = addrtx[1][1];//, printf("{A%d.%d} -> ",addrtx[0][0],addrtx[0][1]);
        else printf("coin777_addrbalance: cant find addrtx.%d of num.%d maxfixed.%d\n",addrtxi,A->num,maxfixed);
    }
    return(unspentind);
}

uint64_t coin777_recalc_addrinfo(struct coin777 *coin,uint32_t addrind,uint32_t lastblocknum)
{
    uint32_t addrtx[2][2],blocknum,unspentind; int32_t i;
    struct coin777_addrinfo A; struct unspent_info U; uint64_t origbalance;
    memset(&A,0,sizeof(A));
    if ( coin777_RWmmap(0,&A,coin,&coin->addrinfos,addrind) == 0 )
    {
        origbalance = A.balance, A.balance = 0;
        for (i=0; i<A.num; i++)
        {
            unspentind = coin777_addrtx(coin,&blocknum,addrtx,&A,addrind,i);
            if ( unspentind == 0 || blocknum >= lastblocknum )
                break;
            if ( coin777_RWmmap(0,&U,coin,&coin->unspents,unspentind & ~(1 << 31)) == 0 )
            {
                if ( (unspentind & (1 << 31)) != 0 )
                    A.balance -= U.value;
                else A.balance += U.value;
            }
        }
        if ( 1 && A.balance != origbalance )
        {
            printf("(%.8f -> %.8f).A%u  addrind.%d maxfixed.%d num.%d block.%u vs %u\n",dstr(origbalance),dstr(A.balance),addrind,addrind,coin777_maxfixed(&A),A.num,blocknum,lastblocknum);
            coin777_RWmmap(1,&A,coin,&coin->addrinfos,addrind);
        }
        return(A.balance);
    } else printf("coin777_unspent cant find addrinfo for addrind.%u\n",addrind);
    return(0);
}

uint64_t coin777_recalc_addrinfos(struct coin777 *coin,uint32_t maxaddrind,uint32_t lastblocknum,uint64_t supply)
{
    uint32_t addrind; uint64_t sum = 0;
    printf("coin777_recalc_addrinfos %.8f vs orig %.8f\n",dstr(coin->addrsum),dstr(supply));
    for (addrind=1; addrind<maxaddrind; addrind++)
        sum += coin777_recalc_addrinfo(coin,addrind,lastblocknum);
    printf(" -> coin777_recalc_addrinfos %.8f vs orig %.8f\n",dstr(sum),dstr(supply));
    return(sum);
}

uint64_t addrinfos_sum(struct coin777 *coin,uint32_t maxaddrind,int32_t syncflag,uint32_t blocknum)
{
    struct coin777_addrinfo A; int64_t sum = 0; int32_t i,fixups = 0; uint64_t lbalance,calcbalance;
    for (i=1; i<maxaddrind; i++)
    {
        if ( coin777_RWmmap(0,&A,coin,&coin->addrinfos,i) == 0 )
        {
            if ( syncflag != 0 )
            {
                //printf("%d %s %.8f %.8f num.%d\n",i,A.coinaddr,dstr(A.balance),dstr(A.syncbalance),A.num);
                if ( syncflag > 0 )
                    A.syncbalance = A.balance, A.syncnum = A.num;//, printf("%.8f ",dstr(A.balance));
                else if ( syncflag < 0 )
                    A.balance = A.syncbalance, A.num = A.syncnum;
                coin777_RWmmap(1,&A,coin,&coin->addrinfos,i);
            }
            coin777_RWmmap(0,&lbalance,coin,&coin->ledger,i);
            if ( lbalance != A.balance )
            {
                calcbalance = coin777_recalc_addrinfo(coin,i,blocknum);
                if ( calcbalance != lbalance )
                {
                    if ( Debuglevel > 2 )
                        printf("addrind.%u ledger %.8f vs %.8f calc %.8f?\n",i,dstr(lbalance),dstr(A.balance),dstr(calcbalance));
                    coin777_RWmmap(1,&calcbalance,coin,&coin->ledger,i);
                    fixups++;
                }
                A.balance = calcbalance;
            }
            if ( 0 && A.balance != 0 )
                printf("%.8f ",dstr(A.balance));
            sum += A.balance;
        }
    }
    if ( fixups != 0 )
        printf("addrinfos_sum @ blocknum.%u neeed %d fixups -> sum %.8f\n",blocknum,fixups,dstr(sum));
    coin->addrsum = sum;
    return(sum);
}

// coin777 add funcs
int32_t coin777_add_addrinfo(struct coin777 *coin,uint32_t addrind,char *coinaddr,int32_t len,uint8_t *script,uint16_t scriptlen,uint32_t blocknum)
{
    struct coin777_addrinfo A; uint8_t *scriptptr;
    memset(&A,0,sizeof(A));
    update_sha256(coin->addrinfos.sha256,&coin->addrinfos.state,(uint8_t *)&blocknum,sizeof(blocknum));
    update_sha256(coin->addrinfos.sha256,&coin->addrinfos.state,(uint8_t *)coinaddr,len);
    update_sha256(coin->addrinfos.sha256,&coin->addrinfos.state,script,scriptlen);
    A.firstblocknum = blocknum;
    A.addrlen = len, memcpy(A.coinaddr,coinaddr,len);
    if ( (scriptlen + A.addrlen) <= sizeof(A.coinaddr) )
    {
        A.scriptlen = scriptlen;
        if ( (scriptptr= coin777_scriptptr(&A)) != 0 )
            memcpy(scriptptr,script,scriptlen), len += scriptlen;
    }
    A.unspents_offset = len;
    if ( (A.unspents_offset & 3) != 0 )
        A.unspents_offset += 4 - (A.unspents_offset & 3);
    if ( A.unspents_offset > (sizeof(A.coinaddr) - 2*sizeof(uint32_t)) )
    {
        A.unspents_offset = sizeof(A.coinaddr);
        printf("overflowed unspentinds[] with unspentoffset.%d for (%s) A.addrlen.%d A.scriptlen %d sizeof(coinaddr) %ld\n",A.unspents_offset,coinaddr,A.addrlen,A.scriptlen,sizeof(A.coinaddr));
        A.unspents_offset = (int16_t)sizeof(A.coinaddr);
    }
    if ( Debuglevel > 2 )
        printf("maxfixed.%d\n",coin777_maxfixed(&A));
    return(coin777_RWmmap(1,&A,coin,&coin->addrinfos,addrind));
}

int32_t coin777_addscript(struct coin777 *coin,uint32_t *scriptindp,uint8_t *script,int32_t scriptlen,int32_t script0flag)
{
    uint32_t scriptind = 0; int32_t retval = 0;
    if ( script0flag == 0 )
    {
        scriptind = (*scriptindp)++;
        retval = coin777_addDB(coin,coin->DBs.transactions,coin->scriptDB.DB,script,scriptlen,&scriptind,sizeof(scriptind));
    }
    if ( Debuglevel > 2 )
        printf("NEW SCRIPT scriptind.%u [%u] script0flag.%d\n",scriptind,(*scriptindp),script0flag);
    return(retval);
}

int32_t coin777_addvout(void *state,uint64_t *creditsp,uint32_t txidind,uint16_t vout,uint32_t unspentind,char *coinaddr,char *scriptstr,uint64_t value,uint32_t *addrindp,uint32_t *scriptindp,uint32_t blocknum)
{
    struct coin777 *coin = state; uint32_t *ptr,addrind,scriptind = 0; int32_t script0flag,tmp,len,scriptlen,havescript = 0;
    uint8_t script[4096]; struct unspent_info U;
    (*creditsp) += value;
    scriptlen = (int32_t)strlen(scriptstr) >> 1, decode_hex(script,scriptlen,scriptstr);
    len = (int32_t)strlen(coinaddr) + 1;
    update_sha256(coin->addrDB.sha256,&coin->addrDB.state,(uint8_t *)coinaddr,len);
    update_sha256(coin->scriptDB.sha256,&coin->scriptDB.state,(uint8_t *)scriptstr,scriptlen << 1);
    if ( Debuglevel > 2 )
        printf("addvout.%d: (%s) (%s) %.8f\n",vout,coinaddr,scriptstr,dstr(value));
    if ( (addrind= coin777_findind(coin,&coin->addrDB,(uint8_t *)coinaddr,len)) == 0 )
    {
        tmp = sizeof(addrind);
        if ( (ptr= coin777_getDB(&addrind,&tmp,coin->DBs.transactions,coin->addrDB.DB,coinaddr,len)) == 0 || addrind == 0 )
        {
            addrind = (*addrindp)++;
            script0flag = coin777_add_addrinfo(coin,addrind,coinaddr,len,script,scriptlen,blocknum);
            coin777_addscript(coin,scriptindp,script,scriptlen,script0flag), havescript = 1;
            coin777_addDB(coin,coin->DBs.transactions,coin->addrDB.DB,coinaddr,len,&addrind,sizeof(addrind));
        }
        else
        {
            if ( addrind == (*addrindp) )
                (*addrindp)++;
            else if ( addrind > (*addrindp) )
                printf("DB returned addrind.%u vs (*addrindp).%u\n",addrind,(*addrindp));
            coin777_addind(coin,&coin->addrDB,coinaddr,len,addrind);
        }
    }
    if ( havescript == 0 && coin777_script0(coin,addrind,script,scriptlen) == 0 )
    {
        //printf("search for (%s)\n",scriptstr);
        if ( (scriptind= coin777_findind(coin,&coin->scriptDB,script,scriptlen)) == 0 )
        {
            tmp = sizeof(scriptind);
            if ( (ptr= coin777_getDB(&scriptind,&tmp,coin->DBs.transactions,coin->scriptDB.DB,script,scriptlen)) == 0 || scriptind == 0 )
                coin777_addscript(coin,scriptindp,script,scriptlen,0);
            else
            {
                if ( Debuglevel > 2 )
                    printf("search for (%s) -> scriptind.%u [%u]\n",scriptstr,scriptind,(*scriptindp));
                if ( scriptind == (*scriptindp) )
                    (*scriptindp)++;
                else if ( scriptind > (*scriptindp) )
                    printf("DB returned scriptind.%u vs (*scriptindp).%u\n",scriptind,(*scriptindp));
                coin777_addind(coin,&coin->scriptDB,script,scriptlen,scriptind);
            }
        }
    }
    if ( Debuglevel > 2 )
        printf("UNSPENT.%u addrind.%u T%u vo%-3d U%u %.8f %s %llx %s\n",unspentind,addrind,txidind,vout,unspentind,dstr(value),coinaddr,*(long long *)script,scriptstr);
    memset(&U,0,sizeof(U)), U.value = value, U.addrind = addrind, coin777_RWmmap(1 | COIN777_SHA256,&U,coin,&coin->unspents,unspentind);
    return(coin777_update_addrinfo(coin,addrind,unspentind,value,blocknum));
}

uint64_t coin777_addvin(void *state,uint64_t *debitsp,uint32_t txidind,uint16_t vin,uint32_t totalspends,char *spent_txidstr,uint16_t spent_vout,uint32_t blocknum)
{
    struct coin777 *coin = state; bits256 txid; int32_t tmp; uint32_t *ptr,unspentind,spent_txidind; struct unspent_info U;
    memset(txid.bytes,0,sizeof(txid)), decode_hex(txid.bytes,sizeof(txid),spent_txidstr);
    if ( (spent_txidind= coin777_findind(coin,&coin->txidDB,txid.bytes,sizeof(txid))) == 0 )
    {
        tmp = sizeof(spent_txidind);
        if ( (ptr= coin777_getDB(&spent_txidind,&tmp,coin->DBs.transactions,coin->txidDB.DB,txid.bytes,sizeof(txid))) == 0 || spent_txidind == 0 || tmp != sizeof(*ptr) )
        {
            printf("cant find %016llx txid.(%s) ptr.%p spent_txidind.%u spendvout.%d from len.%ld (%s)\n",(long long)txid.txid,spent_txidstr,ptr,spent_txidind,spent_vout,sizeof(txid),db777_errstr(coin->DBs.ctl)), debugstop();
            return(-1);
        }
    }
    if ( spent_txidind > txidind )
    {
        printf("coin777_addvin txidind overflow? spent_txidind.%u vs max.%u\n",spent_txidind,txidind), debugstop();
        return(-2);
    }
    if ( coin777_value(coin,&unspentind,&U,spent_txidind,spent_vout) != 0 )
    {
        if ( Debuglevel > 2 )
            printf("SPEND T%u vi%-3d S%u %s vout.%d -> A%u %.8f\n",txidind,vin,totalspends,spent_txidstr,spent_vout,U.addrind,dstr(U.value));
        if ( U.spending_txidind != 0 && U.spending_txidind != txidind )
            printf(" interloper txidind.%u overwrites.%u\n",txidind,U.spending_txidind);
        U.spending_txidind = txidind;
        U.spending_vin = vin;
        coin777_RWmmap(1 | COIN777_SHA256,&unspentind,coin,&coin->spends,totalspends);
        coin777_update_addrinfo(coin,U.addrind,unspentind | (1 << 31),-(int64_t)U.value,blocknum);
        (*debitsp) += U.value;
        return(U.value);
    } else printf("warning: (%s).v%d null value\n",spent_txidstr,spent_vout);
    return(0);
}

int32_t coin777_addtx(void *state,uint32_t blocknum,uint32_t txidind,char *txidstr,uint32_t firstvout,uint16_t numvouts,uint64_t total,uint32_t firstvin,uint16_t numvins)
{
    struct coin777 *coin = state; bits256 txid; uint32_t txoffsets[2];
    memset(txid.bytes,0,sizeof(txid)), decode_hex(txid.bytes,sizeof(txid),txidstr);
    coin777_RWmmap(1 | COIN777_SHA256,&txid,coin,&coin->txidbits,txidind);
    update_sha256(coin->txidDB.sha256,&coin->txidDB.state,(uint8_t *)txidstr,(int32_t)sizeof(txid)*2);
    coin777_addDB(coin,coin->DBs.transactions,coin->txidDB.DB,txid.bytes,sizeof(txid),&txidind,sizeof(txidind));
    if ( Debuglevel > 2 )
        printf("ADDTX.%s: %x T%u U%u + numvouts.%d, S%u + numvins.%d\n",txidstr,*(int *)txid.bytes,txidind,firstvout,numvouts,firstvin,numvins);
    txoffsets[0] = firstvout, txoffsets[1] = firstvin, coin777_RWmmap(1 | COIN777_SHA256,txoffsets,coin,&coin->txoffsets,txidind);
    txoffsets[0] += numvouts, txoffsets[1] += numvins, coin777_RWmmap(1,txoffsets,coin,&coin->txoffsets,txidind+1);
    coin777_addind(coin,&coin->txidDB,txid.bytes,sizeof(txid),txidind);
    return(0);
}

int32_t coin777_addblock(void *state,uint32_t blocknum,char *blockhashstr,char *merklerootstr,uint32_t timestamp,uint64_t minted,uint32_t txidind,uint32_t unspentind,uint32_t numspends,uint32_t addrind,uint32_t scriptind,uint64_t credits,uint64_t debits)
{
    bits256 blockhash,merkleroot; struct coin777 *coin = state; struct coin_offsets zeroB,B,block; int32_t i,err = 0;
    memset(&B,0,sizeof(B));
    //Debuglevel = 3;
    if ( Debuglevel > 2 )
        printf("B.%u T.%u U.%u S.%u A.%u C.%u\n",blocknum,txidind,unspentind,numspends,addrind,scriptind);
    if ( blockhashstr != 0 ) // start of block
    {
        memset(blockhash.bytes,0,sizeof(blockhash)), decode_hex(blockhash.bytes,sizeof(blockhash),blockhashstr);
        memset(merkleroot.bytes,0,sizeof(merkleroot)), decode_hex(merkleroot.bytes,sizeof(merkleroot),merklerootstr);
        B.blockhash = blockhash, B.merkleroot = merkleroot;
    } // else end of block, but called with blocknum+1
    B.timestamp = timestamp, B.txidind = txidind, B.unspentind = unspentind, B.numspends = numspends, B.addrind = addrind, B.scriptind = scriptind;
    B.credits = credits, B.debits = debits;
    for (i=0; i<coin->num; i++)
        B.check[i] = coin->sps[i]->sha256[0];
    if ( coin777_RWmmap(0,&block,coin,&coin->blocks,blocknum) == 0  )
    {
        if ( memcmp(&B,&block,sizeof(B)) != 0 )
        {
            memset(&zeroB,0,sizeof(zeroB));
            if ( memcmp(&B,&zeroB,sizeof(zeroB)) != 0 )
            {
                if ( block.timestamp != 0 && B.timestamp != block.timestamp )
                    err = -2, printf("nonz timestamp.%u overwrites %u\n",B.timestamp,block.timestamp);
                if ( block.txidind != 0 && B.txidind != block.txidind )
                    err = -3, printf("nonz txidind.%u overwrites %u\n",B.txidind,block.txidind);
                if ( block.unspentind != 0 && B.unspentind != block.unspentind )
                    err = -4, printf("nonz unspentind.%u overwrites %u\n",B.unspentind,block.unspentind);
                if ( block.numspends != 0 && B.numspends != block.numspends )
                    err = -5, printf("nonz numspends.%u overwrites %u\n",B.numspends,block.numspends);
                if ( block.addrind != 0 && B.addrind != block.addrind )
                    err = -6, printf("nonz addrind.%u overwrites %u\n",B.addrind,block.addrind);
                if ( block.scriptind != 0 && B.scriptind != block.scriptind )
                    err = -7, printf("nonz scriptind.%u overwrites %u\n",B.scriptind,block.scriptind);
                if ( block.credits != 0 && B.credits != 0 && B.credits != block.credits )
                    err = -8, printf("nonz total %.8f overwrites %.8f\n",dstr(B.credits),dstr(block.credits));
                if ( block.debits != 0 && B.debits != 0 && B.debits != block.debits )
                    err = -9, printf("nonz debits %.8f overwrites %.8f\n",dstr(B.debits),dstr(block.debits));
            }
        }
        coin->latest = B, coin->latestblocknum = blocknum;
        if ( coin777_RWmmap(1 | (blockhashstr != 0)*COIN777_SHA256,&B,coin,&coin->blocks,blocknum) != 0 )
            return(-1);
    }
    return(err);
}

// coin777 sync/resume funcs
struct coin777_hashes *coin777_getsyncdata(struct coin777_hashes *H,struct coin777 *coin,int32_t synci)
{
    struct coin777_hashes *hp; int32_t allocsize = sizeof(*H);
    if ( synci <= 0 )
        synci++;
    if ( (hp= coin777_getDB(H,&allocsize,coin->DBs.transactions,coin->hashDB.DB,&synci,sizeof(synci))) != 0 )
        return(hp);
    else memset(H,0,sizeof(*H));
    printf("couldnt find synci.%d keylen.%ld\n",synci,sizeof(synci));
    return(0);
}

int32_t coin777_syncblocks(struct coin777_hashes *inds,int32_t max,struct coin777 *coin)
{
    struct coin777_hashes H,*hp; int32_t synci,n = 0;
    if ( (hp= coin777_getsyncdata(&H,coin,-1)) != 0 )
    {
        inds[n++] = *hp;
        for (synci=coin->numsyncs; synci>0&&n<max; synci--)
        {
            if ( (hp= coin777_getsyncdata(&H,coin,synci)) != 0 )
                inds[n++] = *hp;
        }
    } else printf("null return from coin777_getsyncdata\n");
    return(n);
}

uint64_t coin777_ledgerhash(char *ledgerhash,struct coin777_hashes *H)
{
    bits256 hashbits;
    if ( H != 0 )
    {
        calc_sha256(0,hashbits.bytes,(uint8_t *)(void *)((long)H + sizeof(H->ledgerhash)),sizeof(*H) - sizeof(H->ledgerhash));
        H->ledgerhash = hashbits.txid;
        if ( ledgerhash != 0 )
            ledgerhash[0] = 0, init_hexbytes_noT(ledgerhash,hashbits.bytes,sizeof(hashbits));
        return(hashbits.txid);
    }
    return(0);
}

uint32_t coin777_hashes(int32_t *syncip,struct coin777_hashes *bestH,struct coin777 *coin,uint32_t refblocknum,int32_t lastsynci)
{
    int32_t i,synci,flag = 0; struct coin777_hashes *hp,H;
    *syncip = -1;
    for (synci=1; synci<=lastsynci; synci++)
    {
        if ( (hp= coin777_getsyncdata(&H,coin,synci)) == 0 || hp->blocknum > refblocknum )
            break;
        *bestH = *hp;
        *syncip = synci;
        flag = 1;
    }
    if ( flag == 0 )
    {
        memset(bestH,0,sizeof(*bestH));
        coin777_getinds(coin,0,&bestH->credits,&bestH->debits,&bestH->timestamp,&bestH->txidind,&bestH->unspentind,&bestH->numspends,&bestH->addrind,&bestH->scriptind);
        bestH->numsyncs = 1;
        for (i=0; i<coin->num; i++)
            update_sha256(bestH->sha256[i],&bestH->states[i],0,0);
        bestH->ledgerhash = coin777_ledgerhash(0,bestH);
    }
    return(bestH->blocknum);
}

// coin777 init funcs
uint32_t coin777_startblocknum(struct coin777 *coin,uint32_t synci)
{
    struct coin777_hashes H,*hp; struct coin_offsets B; int32_t i; uint32_t blocknum = 0; uint64_t ledgerhash;
    if ( (hp= coin777_getsyncdata(&H,coin,synci)) == &H )
    {
        coin->blocknum = blocknum = hp->blocknum, coin->numsyncs = hp->numsyncs;
        if ( coin777_RWmmap(0,&B,coin,&coin->blocks,blocknum) == 0  )
        {
            B.credits = hp->credits, B.debits = hp->debits;
            B.timestamp = hp->timestamp, B.txidind = hp->txidind, B.unspentind = hp->unspentind, B.numspends = hp->numspends, B.addrind = hp->addrind, B.scriptind = hp->scriptind;
            coin777_RWmmap(1,&B,coin,&coin->blocks,blocknum);
        }
        if ( hp->addrind > 1 )
            coin->addrsum = addrinfos_sum(coin,hp->addrind,-1,blocknum);
        ledgerhash = coin777_ledgerhash(0,hp);
        for (i=0; i<coin->num; i++)
        {
            coin->sps[i]->state = H.states[i];
            memcpy(coin->sps[i]->sha256,H.sha256[i],sizeof(H.sha256[i]));
            printf("%08x ",*(uint32_t *)H.sha256[i]);
        }
        printf("RESTORED.%d -> block.%u ledgerhash %08x addrsum %.8f maxaddrind.%u supply %.8f\n",synci,blocknum,(uint32_t)ledgerhash,dstr(coin->addrsum),hp->addrind,dstr(B.credits)-dstr(B.debits));
    } else printf("ledger_getnearest error getting last\n");
    return(blocknum);// == 0 ? blocknum : blocknum - 1);
}

struct coin777_state *coin777_stateinit(struct env777 *DBs,struct coin777_state *sp,char *coinstr,char *subdir,char *name,char *compression,int32_t flags,int32_t valuesize)
{
    safecopy(sp->name,name,sizeof(sp->name));
    sp->flags = flags;
    portable_mutex_init(&sp->mutex);
    if ( DBs != 0 )
    {
        safecopy(DBs->coinstr,coinstr,sizeof(DBs->coinstr));
        safecopy(DBs->subdir,subdir,sizeof(DBs->subdir));
    }
    update_sha256(sp->sha256,&sp->state,0,0);
    sp->itemsize = valuesize;
    if ( DBs != 0 )
        sp->DB = db777_open(0,DBs,name,compression,flags,valuesize);
    return(sp);
}

#define COIN777_ADDRINFOS 0 //
#define COIN777_BLOCKS 1 //
#define COIN777_TXOFFSETS 2 //
#define COIN777_TXIDBITS 3 //
#define COIN777_UNSPENTS 4 //
#define COIN777_SPENDS 5 //
#define COIN777_LEDGER 6 //
#define COIN777_TXIDS 7 //
#define COIN777_ADDRS 8 //
#define COIN777_SCRIPTS 9 //
#define COIN777_ACTIVES 10
#define COIN777_HASHES 11

void coin777_initDBenv(struct coin777 *coin)
{
    char *subdir="",*coinstr = coin->name; int32_t n = 0;
    if ( n == COIN777_ADDRINFOS )
        coin->sps[n++] = coin777_stateinit(0,&coin->addrinfos,coinstr,subdir,"addrinfos","zstd",DB777_VOLATILE,sizeof(struct coin777_addrinfo));
    if ( n == COIN777_BLOCKS )
        coin->sps[n++] = coin777_stateinit(0,&coin->blocks,coinstr,subdir,"blocks","zstd",DB777_VOLATILE,sizeof(struct coin_offsets));
    if ( n == COIN777_TXOFFSETS )
        coin->sps[n++] = coin777_stateinit(0,&coin->txoffsets,coinstr,subdir,"txoffsets","zstd",0,sizeof(uint32_t) * 2);
    if ( n == COIN777_TXIDBITS )
        coin->sps[n++] = coin777_stateinit(0,&coin->txidbits,coinstr,subdir,"txidbits",0,0,sizeof(bits256));
    if ( n == COIN777_UNSPENTS )
        coin->sps[n++] = coin777_stateinit(0,&coin->unspents,coinstr,subdir,"unspents","zstd",DB777_VOLATILE,sizeof(struct unspent_info));
    if ( n == COIN777_SPENDS )
        coin->sps[n++] = coin777_stateinit(0,&coin->spends,coinstr,subdir,"spends","zstd",0,sizeof(uint32_t));
    if ( n == COIN777_LEDGER )
        coin->sps[n++] = coin777_stateinit(0,&coin->ledger,coinstr,subdir,"ledger","zstd",DB777_VOLATILE,sizeof(uint64_t));
    
    if ( n == COIN777_TXIDS )
        coin->sps[n++] = coin777_stateinit(&coin->DBs,&coin->txidDB,coinstr,subdir,"txids",0,DB777_HDD,sizeof(uint32_t));
    if ( n == COIN777_ADDRS )
        coin->sps[n++] = coin777_stateinit(&coin->DBs,&coin->addrDB,coinstr,subdir,"addrs","zstd",DB777_HDD,sizeof(uint32_t));
    if ( n == COIN777_SCRIPTS )
        coin->sps[n++] = coin777_stateinit(&coin->DBs,&coin->scriptDB,coinstr,subdir,"scripts","zstd",DB777_HDD,sizeof(uint32_t));
    if ( n == COIN777_ACTIVES )
        coin->sps[n++] = coin777_stateinit(&coin->DBs,&coin->activeDB,coinstr,subdir,"actives","zstd",DB777_HDD,sizeof(uint32_t));
    coin->num = n;
    if ( n == COIN777_HASHES )
        coin->sps[n] = coin777_stateinit(&coin->DBs,&coin->hashDB,coinstr,subdir,"hashes","zstd",DB777_HDD,sizeof(struct coin777_hashes));
    else printf("coin777_initDBenv mismatched COIN777_HASHES.%d vs n.%d\n",COIN777_HASHES,n), exit(-1);
    env777_start(0,&coin->DBs,0);
}

int32_t coin777_initmmap(struct coin777 *coin,uint32_t blocknum,uint32_t txidind,uint32_t addrind,uint32_t scriptind,uint32_t unspentind,uint32_t totalspends)
{
    coin->blocks.table = coin777_ensure(coin,&coin->blocks,blocknum);
    coin->txoffsets.table = coin777_ensure(coin,&coin->txoffsets,txidind);
    coin->txidbits.table = coin777_ensure(coin,&coin->txidbits,txidind);
    coin->unspents.table = coin777_ensure(coin,&coin->unspents,unspentind);
    coin->addrinfos.table = coin777_ensure(coin,&coin->addrinfos,addrind);
    coin->ledger.table = coin777_ensure(coin,&coin->ledger,addrind);
    coin->spends.table = coin777_ensure(coin,&coin->spends,totalspends);
    return(0);
}

// coin777 block parser
int32_t coin777_getinds(void *state,uint32_t blocknum,uint64_t *creditsp,uint64_t *debitsp,uint32_t *timestampp,uint32_t *txidindp,uint32_t *unspentindp,uint32_t *numspendsp,uint32_t *addrindp,uint32_t *scriptindp)
{
    struct coin777 *coin = state; struct coin_offsets block;
    if ( coin->blocks.table == 0 ) // bootstrap requires coin_offsets DB before anything else
        coin777_stateinit(0,&coin->blocks,coin->name,"","blocks","zstd",DB777_VOLATILE,sizeof(struct coin_offsets));
    if ( blocknum == 0 )
        *txidindp = *unspentindp = *numspendsp = *addrindp = *scriptindp = 1, *creditsp = *debitsp = *timestampp = 0;
    else
    {
        coin777_RWmmap(0,&block,coin,&coin->blocks,blocknum);
        *creditsp = block.credits, *debitsp = block.debits;
        *timestampp = block.timestamp, *txidindp = block.txidind;
        *unspentindp = block.unspentind, *numspendsp = block.numspends, *addrindp = block.addrind, *scriptindp = block.scriptind;
        if ( blocknum == coin->startblocknum )
            printf("(%.8f - %.8f) supply %.8f blocknum.%u loaded txidind.%u unspentind.%u numspends.%u addrind.%u scriptind.%u\n",dstr(*creditsp),dstr(*debitsp),dstr(*creditsp)-dstr(*debitsp),blocknum,*txidindp,*unspentindp,*numspendsp,*addrindp,*scriptindp);
    }
    return(0);
}

uint64_t coin777_flush(struct coin777 *coin,uint32_t blocknum,int32_t numsyncs,uint64_t credits,uint64_t debits,uint32_t timestamp,uint32_t txidind,uint32_t numrawvouts,uint32_t numrawvins,uint32_t addrind,uint32_t scriptind)
{
    int32_t i,retval = 0; struct coin777_hashes H;//,*hp; uint64_t *balances;
    memset(&H,0,sizeof(H)); H.blocknum = blocknum, H.numsyncs = numsyncs, H.credits = credits, H.debits = debits;
    H.timestamp = timestamp, H.txidind = txidind, H.unspentind = numrawvouts, H.numspends = numrawvins, H.addrind = addrind, H.scriptind = scriptind;
    if ( numsyncs >= 0 )
        addrinfos_sum(coin,addrind,1,blocknum);
    for (i=0; i<=coin->num; i++)
    {
        if ( numsyncs >= 0 && coin->sps[i]->M.fileptr != 0 )
            sync_mappedptr(&coin->sps[i]->M,0);
        if ( i < coin->num )
        {
            H.states[i] = coin->sps[i]->state;
            memcpy(H.sha256[i],coin->sps[i]->sha256,sizeof(H.sha256[i]));
        }
    }
    H.ledgerhash = coin777_ledgerhash(0,&H);
    if ( numsyncs < 0 )
    {
        for (i=0; i<coin->num; i++)
            printf("%08x ",*(int *)H.sha256[i]);
    }
    if ( numsyncs >= 0 )
    {
        printf("SYNCNUM.%d -> %d addrsum %.8f addrind.%u supply %.8f | txids.%u addrs.%u scripts.%u unspents.%u spends.%u ledgerhash %08x\n",numsyncs,blocknum,dstr(coin->addrsum),addrind,dstr(credits)-dstr(debits),coin->latest.txidind,coin->latest.addrind,coin->latest.scriptind,coin->latest.unspentind,coin->latest.numspends,(uint32_t)H.ledgerhash);
        if ( coin777_addDB(coin,coin->DBs.transactions,coin->hashDB.DB,&numsyncs,sizeof(numsyncs),&H,sizeof(H)) != 0 )
            printf("error saving numsyncs.0 retval.%d %s\n",retval,db777_errstr(coin->DBs.ctl)), sleep(30);
        if ( numsyncs > 0 )
        {
            numsyncs = 0;
            if ( (retval = coin777_addDB(coin,coin->DBs.transactions,coin->hashDB.DB,&numsyncs,sizeof(numsyncs),&H,sizeof(H))) != 0 )
                printf("error saving numsyncs.0 retval.%d %s\n",retval,db777_errstr(coin->DBs.ctl)), sleep(30);
        }
    }
    return(H.ledgerhash);
}

int32_t coin777_parse(struct coin777 *coin,uint32_t RTblocknum,int32_t syncflag,int32_t minconfirms)
{
    uint32_t blocknum,dispflag,ledgerhash=0,allocsize,timestamp,txidind,numrawvouts,numrawvins,addrind,scriptind; int32_t numtx,err;
    uint64_t origsize,supply,oldsupply,credits,debits; double estimate,elapsed,startmilli;
    blocknum = coin->blocknum;
    if ( blocknum <= (RTblocknum - minconfirms) )
    {
        startmilli = milliseconds();
        dispflag = 1 || (blocknum > RTblocknum - 1000);
        dispflag += ((blocknum % 100) == 0);
        if ( coin777_getinds(coin,blocknum,&credits,&debits,&timestamp,&txidind,&numrawvouts,&numrawvins,&addrind,&scriptind) == 0 )
        {
            if ( coin->DBs.transactions == 0 )
                coin->DBs.transactions = sp_begin(coin->DBs.env);
            supply = (credits - debits), origsize = coin->totalsize;
            if ( syncflag != 0 || blocknum == coin->startblocknum )
            {
                coin->addrsum = addrinfos_sum(coin,addrind,0,blocknum);
                if ( 0 && coin->addrsum != supply )
                {
                    coin->addrsum = coin777_recalc_addrinfos(coin,addrind,blocknum,supply);
                    if ( coin->addrsum != supply )
                        printf("recalc new error: [%.8f]\n",dstr(coin->addrsum) - dstr(supply)), debugstop();
                }
            }
            oldsupply = supply;
            if ( syncflag != 0 && blocknum > (coin->startblocknum + 1) )
                ledgerhash = (uint32_t)coin777_flush(coin,blocknum,++coin->numsyncs,credits,debits,timestamp,txidind,numrawvouts,numrawvins,addrind,scriptind);
            else ledgerhash = (uint32_t)coin777_flush(coin,blocknum,-1,credits,debits,timestamp,txidind,numrawvouts,numrawvins,addrind,scriptind);
            numtx = parse_block(coin,&credits,&debits,&txidind,&numrawvouts,&numrawvins,&addrind,&scriptind,coin->name,coin->serverport,coin->userpass,blocknum,coin777_addblock,coin777_addvin,coin777_addvout,coin777_addtx);
            if ( coin->DBs.transactions != 0 )
            {
                while ( (err= sp_commit(coin->DBs.transactions)) != 0 )
                {
                    printf("ledger_commit: sp_commit error.%d\n",err);
                    if ( err < 0 )
                        break;
                    msleep(1000);
                }
                coin->DBs.transactions = 0;
            }
            supply = (credits - debits);
            dxblend(&coin->calc_elapsed,(milliseconds() - startmilli),.99);
            allocsize = (uint32_t)(coin->totalsize - origsize);
            estimate = estimate_completion(coin->startmilli,blocknum - coin->startblocknum,RTblocknum-blocknum)/60000;
            elapsed = (milliseconds() - coin->startmilli)/60000.;
            if ( dispflag != 0 )
            {
                extern int32_t Duplicate,Mismatch,Added,Linked,Numgets;
                printf("%.3f %-5s [lag %-5d] %-6u %.8f %.8f (%.8f) [%.8f] %13.8f | dur %.2f %.2f %.2f | len.%-5d %s %.1f | H%d E%d R%d W%d %08x\n",coin->calc_elapsed/1000.,coin->name,RTblocknum-blocknum,blocknum,dstr(oldsupply),dstr(coin->addrsum),dstr(oldsupply)-dstr(coin->addrsum),dstr(supply)-dstr(oldsupply),dstr(coin->minted != 0 ? coin->minted : (supply - oldsupply)),elapsed,elapsed+(RTblocknum-blocknum)*coin->calc_elapsed/60000,elapsed+estimate,allocsize,_mbstr(coin->totalsize),(double)coin->totalsize/blocknum,Duplicate,Mismatch,Numgets,Added,ledgerhash);
            }
            coin->blocknum++;
            return(1);
        }
        else
        {
            printf("coin777 error getting inds for blocknum%u\n",blocknum);
            return(0);
        }
    } else printf("blocknum.%d > RTblocknum.%d - minconfirms.%d\n",blocknum,RTblocknum,minconfirms);
    return(0);
}

int32_t coin777_replayblock(struct coin777_hashes *hp,struct coin777 *coin,uint32_t blocknum,int32_t synci,int32_t verifyflag)
{
    struct coin_offsets B,nextB; struct unspent_info U; struct coin777_addrinfo A;
    uint32_t txidind,spendind,unspentind,scriptind,txoffsets[2],nexttxoffsets[2],tmp[2]; bits256 txid;
    char scriptstr[4096],txidstr[65]; uint8_t *scriptptr,script[8193],buf[32]; int32_t i,scriptlen,buflen,allocsize = 0,errs = 0;
    if ( coin777_RWmmap(0,&B,coin,&coin->blocks,blocknum) == 0 && coin777_RWmmap(0,&nextB,coin,&coin->blocks,blocknum+1) == 0 )
    {
        for (i=0; i<coin->num; i++)
            printf("%02x.%02x ",hp->sha256[i][0],hp->sha256[i][0] ^ B.check[i]);
        if ( B.txidind != hp->txidind || B.txidind != hp->txidind || B.txidind != hp->txidind || B.txidind != hp->txidind || B.txidind != hp->txidind || B.txidind != hp->txidind || B.credits != hp->credits || B.debits != hp->debits )
        {
            printf("coin777_replayblock.%d: ind mismatch (%u %u %u %u %u) vs (%u %u %u %u %u) || %.8f %.8f vs %.8f %.8f\n",blocknum,B.txidind,B.addrind,B.scriptind,B.unspentind,B.numspends,hp->txidind,hp->addrind,hp->scriptind,hp->unspentind,hp->numspends,dstr(B.credits),dstr(B.debits),dstr(hp->credits),dstr(hp->debits));
        }
        if ( blocknum != 0 )
            update_sha256(hp->sha256[COIN777_BLOCKS],&hp->states[COIN777_BLOCKS],(uint8_t *)&B,(int32_t)sizeof(B));
        allocsize += sizeof(B);
        for (txidind=B.txidind; txidind<nextB.txidind; txidind++,hp->txidind++)
        {
            if ( coin777_RWmmap(0,&txid,coin,&coin->txidbits,txidind) != 0 )
                errs++, printf("error getting txid.%u\n",txidind);
            else if ( coin777_RWmmap(0,txoffsets,coin,&coin->txoffsets,txidind) == 0 && coin777_RWmmap(0,nexttxoffsets,coin,&coin->txoffsets,txidind+1) == 0 )
            {
                init_hexbytes_noT(txidstr,txid.bytes,sizeof(txid));
                update_sha256(hp->sha256[COIN777_TXIDS],&hp->states[COIN777_TXIDS],(uint8_t *)txidstr,(int32_t)sizeof(txid)*2);
                update_sha256(hp->sha256[COIN777_TXIDBITS],&hp->states[COIN777_TXIDBITS],txid.bytes,sizeof(txid));
                update_sha256(hp->sha256[COIN777_TXOFFSETS],&hp->states[COIN777_TXOFFSETS],(uint8_t *)txoffsets,sizeof(txoffsets));
                allocsize += sizeof(txid)*2 + sizeof(txoffsets);
                for (unspentind=txoffsets[0]; unspentind<nexttxoffsets[0]; unspentind++,hp->unspentind++)
                {
                    if ( coin777_RWmmap(0,&U,coin,&coin->unspents,unspentind) == 0 && coin777_RWmmap(0,&A,coin,&coin->addrinfos,U.addrind) == 0 )
                    {
                        allocsize += sizeof(U);
                        hp->credits += U.value;
                        if ( (scriptptr= coin777_scriptptr(&A)) != 0 )
                            init_hexbytes_noT(scriptstr,scriptptr,A.scriptlen);
                        else
                        {
                            strcpy(scriptstr,"get big script");
                            if ( (scriptind= coin777_scriptind(&tmp[0],coin,A.coinaddr,scriptstr)) == hp->scriptind )
                                hp->scriptind++;
                        }
                        scriptlen = ((int32_t)strlen(scriptstr) >> 1);
                        decode_hex(script,scriptlen,scriptstr);
                        if ( U.addrind == hp->addrind && A.firstblocknum == blocknum )
                        {
                            hp->addrind++;
                            allocsize += sizeof(A);
                            update_sha256(hp->sha256[COIN777_ADDRINFOS],&hp->states[COIN777_ADDRINFOS],(uint8_t *)&blocknum,sizeof(blocknum));
                            update_sha256(hp->sha256[COIN777_ADDRINFOS],&hp->states[COIN777_ADDRINFOS],(uint8_t *)A.coinaddr,A.addrlen);
                            update_sha256(hp->sha256[COIN777_ADDRINFOS],&hp->states[COIN777_ADDRINFOS],script,scriptlen);
                        }
                        update_sha256(hp->sha256[COIN777_UNSPENTS],&hp->states[COIN777_UNSPENTS],(uint8_t *)&U,sizeof(U));
                        update_sha256(hp->sha256[COIN777_SCRIPTS],&hp->states[COIN777_SCRIPTS],script,scriptlen);
                        buflen = coin777_activebuf(buf,U.value,U.addrind,blocknum);
                        update_sha256(hp->sha256[COIN777_LEDGER],&hp->states[COIN777_LEDGER],buf,buflen);
                        tmp[0] = U.addrind, tmp[1] = unspentind, update_sha256(hp->sha256[COIN777_ACTIVES],&hp->states[COIN777_ACTIVES],(uint8_t *)tmp,sizeof(tmp));
                    } else errs++, printf("error getting unspendid.%u\n",unspentind);
                }
                for (spendind=txoffsets[1]; spendind<nexttxoffsets[1]; spendind++,hp->numspends++)
                {
                    if ( coin777_RWmmap(0,&unspentind,coin,&coin->spends,spendind) == 0 )
                    {
                        allocsize += sizeof(unspentind);
                        update_sha256(hp->sha256[COIN777_SPENDS],&hp->states[COIN777_SPENDS],(uint8_t *)&unspentind,sizeof(unspentind));
                        if ( coin777_RWmmap(0,&U,coin,&coin->unspents,unspentind) == 0 )
                        {
                            hp->debits += U.value;
                            buflen = coin777_activebuf(buf,-U.value,U.addrind,blocknum);
                            update_sha256(hp->sha256[COIN777_LEDGER],&hp->states[COIN777_LEDGER],buf,buflen);
                            tmp[0] = U.addrind, tmp[1] = unspentind | (1 << 31), update_sha256(hp->sha256[COIN777_ACTIVES],&hp->states[COIN777_ACTIVES],(uint8_t *)tmp,sizeof(tmp));
                            printf("-(u%d %.8f) ",unspentind,dstr(U.value));
                        }
                        else errs++, printf("couldnt find spend ind.%u\n",unspentind);
                    }
                    else errs++, printf("error getting spendind.%u\n",spendind);
                }
                printf("numvins.%d\n",nexttxoffsets[1] - txoffsets[1]);
            }
        }
        printf("blocknum.%u supply %.8f numtx.%d allocsize.%d\n",blocknum,dstr(B.credits) - dstr(B.debits),nextB.txidind - B.txidind,allocsize);
    }
    hp->timestamp = B.timestamp, hp->numsyncs = synci;
    hp->ledgerhash = coin777_ledgerhash(0,hp);
    return(-errs);
}

int32_t coin777_replayblocks(struct coin777 *coin,uint32_t startblocknum,uint32_t endblocknum,int32_t verifyflag)
{
    struct coin777_hashes H,endH; uint32_t blocknum; int32_t startsynci,endsynci,errs = 0;
    if ( (blocknum= coin777_hashes(&startsynci,&H,coin,startblocknum,100000)) != startblocknum )
        errs = -1, printf("cant find hashes for startblocknum.%u closest is %u\n",startblocknum,blocknum);
    else if ( (blocknum= coin777_hashes(&endsynci,&endH,coin,endblocknum,100000)) != startblocknum )
        errs = -2, printf("cant find hashes for endblocknum.%u closest is %u\n",endblocknum,blocknum);
    else
    {
        for (blocknum=startblocknum; blocknum<endblocknum; blocknum++)
            if ( coin777_replayblock(&H,coin,blocknum,endsynci,verifyflag) != 0 )
            {
                printf("coin777_replayblocks error on blocknum.%u\n",blocknum);
                return(-3);
            }
    }
    return(0);
}
#endif
#endif
