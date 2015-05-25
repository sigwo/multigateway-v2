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

struct coin777_hashes { uint64_t ledgerhash; uint32_t blocknum,numsyncs; uint8_t sha256[10][256 >> 3]; struct sha256_state states[10]; };
struct coin_offsets { bits256 blockhash,merkleroot; uint64_t total,spent; uint32_t timestamp,txidind,unspentind,numspends,addrind,scriptind; };
struct unspent_info { uint64_t value; uint32_t addrind,spending_txidind; uint16_t spending_vin; };
struct hashed_uint32 { UT_hash_handle hh; uint32_t ind; };

struct coin777_addrinfo
{
    uint64_t balance;
    uint32_t firstblocknum,numunspents:28,notify:1,pending:1,MGW:1,dirty:1;
    uint16_t scriptlen;
    uint8_t addrlen,unspents_offset;
    char coinaddr[256 - 16];
};

struct Qtx { struct queueitem DL; bits256 txid; uint32_t txidind; };
struct Qaddr { struct queueitem DL; uint32_t addrind; char coinaddr[]; };
struct Qactives { struct queueitem DL; uint32_t unspentind,addrtx[2]; };
struct Qscript { struct queueitem DL; uint32_t scriptind; uint16_t scriptlen; char script[]; };
#define COIN777_SHA256 256

struct coin777
{
    char name[16],serverport[64],userpass[128],*jsonstr;
    cJSON *argjson;
    double lastgetinfo;
    struct ramchain ramchain;
    int32_t use_addmultisig,minconfirms;
    struct packed_info P;
    
    uint64_t credits,debits,minted,addrsum; double calc_elapsed,startmilli;
    uint32_t latestblocknum,blocknum,numsyncs,RTblocknum,startblocknum,endblocknum,needbackup,num,syncfreq;
    struct coin_offsets latest; long totalsize;
    struct env777 DBs;  struct coin777_state *sps[10],txids,addrs,scripts,blocks,txoffsets,txidbits,unspents,spends,addrinfos,actives,hashes;
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
struct packedblock *coin777_packrawblock(struct coin777 *coin,struct rawblock *raw);
int32_t coin777_unpackblock(struct rawblock *raw,struct packedblock *packed,uint32_t blocknum);
void ram_clear_rawblock(struct rawblock *raw,int32_t totalflag);
void coin777_disprawblock(struct rawblock *raw);
void ensure_packedptrs(struct coin777 *coin);
void ramchain_setpackedblock(struct ramchain *ramchain,struct packedblock *packed,uint32_t blocknum);
struct packedblock *ramchain_getpackedblock(void *space,int32_t *lenp,struct ramchain *ramchain,uint32_t blocknum);
uint16_t packed_crc16(struct packedblock *packed);

int32_t coin777_parse(struct coin777 *coin,uint32_t RTblocknum,int32_t syncflag,int32_t minconfirms);
//int32_t coin777_processQs(struct coin777 *coin);
uint64_t coin777_permsize(struct coin777 *coin);
void coin777_initenv(struct coin777 *coin,uint32_t blocknum,uint32_t txidind,uint32_t addrind,uint32_t scriptind,uint32_t unspentind,uint32_t totalspends);
int32_t coin777_sync(struct coin777 *coin);

#endif
#else
#ifndef crypto777_coins777_c
#define crypto777_coins777_c

#ifndef crypto777_coins777_h
#define DEFINES_ONLY
#include "coins777.c"
#endif

void debugstop();

uint64_t parse_voutsobj(int32_t (*voutfuncp)(void *state,uint32_t txidind,uint16_t vout,uint32_t unspentind,char *coinaddr,char *script,uint64_t value,uint32_t *addrindp,uint32_t *scriptindp),void *state,uint32_t txidind,uint32_t *firstvoutp,uint16_t *txnumvoutsp,uint32_t *numrawvoutsp,uint32_t *addrindp,uint32_t *scriptindp,cJSON *voutsobj)
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
            if ( (*voutfuncp)(state,txidind,i,(*numrawvoutsp),coinaddr,script,value,addrindp,scriptindp) != 0 )
                printf("error vout.%d numrawvouts.%u\n",i,(*numrawvoutsp));
        }
    } else (*txnumvoutsp) = 0, printf("error with vouts\n");
    return(total);
}

uint64_t parse_vinsobj(uint64_t (*vinfuncp)(void *state,uint32_t txidind,uint16_t vin,uint32_t totalspends,char *spendtxidstr,uint16_t spendvout),void *state,uint32_t txidind,uint32_t *firstvinp,uint16_t *txnumvinsp,uint32_t *numrawvinsp,cJSON *vinsobj)
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
            if ( (value= (*vinfuncp)(state,txidind,i,(*numrawvinsp),txidstr,(int)get_cJSON_int(item,"vout"))) == 0 )
                printf("error vin.%d numrawvins.%u\n",i,(*numrawvinsp));
            total += value;
        }
    } else (*txnumvinsp) = 0, printf("error with vins\n");
    return(total);
}

int32_t parse_block(void *state,uint32_t *txidindp,uint32_t *numrawvoutsp,uint32_t *numrawvinsp,uint32_t *addrindp,uint32_t *scriptindp,char *coinstr,char *serverport,char *userpass,uint32_t blocknum,
    int32_t (*blockfuncp)(void *state,uint32_t blocknum,char *blockhash,char *merkleroot,uint32_t timestamp,uint64_t minted,uint32_t txidind,uint32_t unspentind,uint32_t numspends,uint32_t addrind,uint32_t scriptind,uint64_t total,uint64_t spent),
    uint64_t (*vinfuncp)(void *state,uint32_t txidind,uint16_t vin,uint32_t totalspends,char *spendtxidstr,uint16_t spendvout),
    int32_t (*voutfuncp)(void *state,uint32_t txidind,uint16_t vout,uint32_t unspentind,char *coinaddr,char *script,uint64_t value,uint32_t *addrindp,uint32_t *scriptindp),
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
                if ( (*blockfuncp)(state,blocknum,blockhash,merkleroot,timestamp,minted,(*txidindp),(*numrawvoutsp),(*numrawvinsp),(*addrindp),(*scriptindp),0,0) != 0 )
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
                            total += parse_voutsobj(voutfuncp,state,(*txidindp),&firstvout,&numvouts,numrawvoutsp,addrindp,scriptindp,cJSON_GetObjectItem(txjson,"vout"));
                            spent += parse_vinsobj(vinfuncp,state,(*txidindp),&firstvin,&numvins,numrawvinsp,cJSON_GetObjectItem(txjson,"vin"));
                            free_json(txjson);
                        } else printf("update_txid_infos parse error.(%s)\n",txidjsonstr);
                        free(txidjsonstr);
                    }
                    else if ( blocknum != 0 )
                        printf("error getting.(%s) blocknum.%d\n",txidstr,blocknum);
                    if ( (*txfuncp)(state,blocknum,(*txidindp),txidstr,firstvout,numvouts,total,firstvin,numvins) != 0 )
                        printf("error adding txidind.%u blocknum.%u txind.%d\n",(*txidindp),blocknum,txind);
                }
                if ( (*blockfuncp)(state,blocknum+1,0,0,0,0,(*txidindp),(*numrawvoutsp),(*numrawvinsp),(*addrindp),(*scriptindp),total,spent) != 0 )
                    printf("error finishing blocknum.%u\n",blocknum);
            } else printf("error _get_blocktxarray for block.%d got %d n.%d\n",blocknum,checkblocknum,numtx);
        } else printf("blocknum.%u mismatched with %u\n",blocknum,get_API_int(cJSON_GetObjectItem(json,"height"),0));
        free_json(json);
    } else printf("get_blockjson error parsing.(%s)\n",txidstr);
    if ( Debuglevel > 2 )
        printf("BLOCK.%d: numtx.%d minted %.8f rawnumvins.%d rawnumvouts.%d\n",blocknum,numtx,dstr(minted),(*numrawvinsp),(*numrawvoutsp));
    return(numtx);
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
        ensure_filesize(fname,needed);
    }
    if ( sp->M.fileptr == 0 )
    {
        if ( init_mappedptr(&sp->MEM.ptr,&sp->M,0,rwflag,fname) != 0 )
        {
            sp->MEM.size = sp->M.allocsize;
            sp->maxitems = (uint32_t)(sp->MEM.size / sp->itemsize);
            memset((void *)((long)sp->M.fileptr + prevsize),0,(sp->MEM.size - prevsize));
            printf("%s maxitems.%u (MEMsize.%ld / itemsize.%d) prevsize.%ld needed.%ld\n",sp->name,sp->maxitems,sp->MEM.size,sp->itemsize,prevsize,needed);
        }
    }
    if ( (sp->table= sp->M.fileptr) == 0 )
        printf("couldnt map %s\n",fname);
    return(sp->table);
}

void coin777_initenv(struct coin777 *coin,uint32_t blocknum,uint32_t txidind,uint32_t addrind,uint32_t scriptind,uint32_t unspentind,uint32_t totalspends)
{
    char *subdir="",*coinstr = coin->name; int32_t n = 0;
    coin->sps[n++] = coin777_stateinit(&coin->DBs,&coin->txids,coinstr,subdir,"txids",0,DB777_HDD,sizeof(uint32_t));
    coin->sps[n++] = coin777_stateinit(&coin->DBs,&coin->addrs,coinstr,subdir,"addrs","zstd",DB777_HDD,sizeof(uint32_t));
    coin->sps[n++] = coin777_stateinit(&coin->DBs,&coin->scripts,coinstr,subdir,"scripts","zstd",DB777_HDD,sizeof(uint32_t));
    coin->sps[n++] = coin777_stateinit(&coin->DBs,&coin->actives,coinstr,subdir,"actives","zstd",DB777_HDD,sizeof(uint32_t));
    coin777_stateinit(&coin->DBs,&coin->hashes,coinstr,subdir,"hashes","zstd",DB777_HDD,sizeof(struct coin777_hashes));
    
    coin->sps[n++] = coin777_stateinit(0,&coin->blocks,coinstr,subdir,"blocks","zstd",DB777_VOLATILE,sizeof(struct coin_offsets));
    coin->sps[n++] = coin777_stateinit(0,&coin->txoffsets,coinstr,subdir,"txoffsets","zstd",0,sizeof(uint32_t) * 2);
    coin->sps[n++] = coin777_stateinit(0,&coin->txidbits,coinstr,subdir,"txidbits",0,0,sizeof(bits256));
    coin->sps[n++] = coin777_stateinit(0,&coin->unspents,coinstr,subdir,"unspents","zstd",DB777_VOLATILE,sizeof(struct unspent_info));
    coin->sps[n++] = coin777_stateinit(0,&coin->addrinfos,coinstr,subdir,"addrinfos","zstd",DB777_VOLATILE,sizeof(struct coin777_addrinfo));
    coin->sps[n++] = coin777_stateinit(0,&coin->spends,coinstr,subdir,"spends","zstd",0,sizeof(uint32_t));
    coin->num = n;
    coin->blocks.table = coin777_ensure(coin,&coin->blocks,blocknum);
    coin->txoffsets.table = coin777_ensure(coin,&coin->txoffsets,txidind);
    coin->txidbits.table = coin777_ensure(coin,&coin->txidbits,txidind);
    coin->unspents.table = coin777_ensure(coin,&coin->unspents,unspentind);
    coin->addrinfos.table = coin777_ensure(coin,&coin->addrinfos,addrind);
    coin->spends.table = coin777_ensure(coin,&coin->spends,totalspends);
    env777_start(0,&coin->DBs,0);
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
    }
    return(retval);
}

void *_coin777_itemptr(struct coin777 *coin,struct coin777_state *sp,uint32_t ind)
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
            if ( (ptr= db777_get(value,&size,coin->DBs.transactions,sp->DB,&rawind,sizeof(rawind))) == 0 || size != sp->itemsize )
                return(-1);
            return(0);
        }
    }
    else
    {
        portable_mutex_lock(&sp->mutex);
        if ( (ptr= _coin777_itemptr(coin,sp,rawind)) != 0 )
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
            else  memcpy(value,ptr,sp->itemsize);
        } else retval = -2;
        portable_mutex_unlock(&sp->mutex);
    }
    return(retval);
}

int32_t coin777_createaddr(struct coin777 *coin,uint32_t addrind,char *coinaddr,int32_t len,uint8_t *script,uint16_t scriptlen)
{
    struct coin777_addrinfo A;
    memset(&A,0,sizeof(A));
    A.addrlen = len;
    A.scriptlen = scriptlen;
    memcpy(A.coinaddr,coinaddr,len);
    memcpy(&A.coinaddr[len],script,scriptlen), len += scriptlen;
    A.unspents_offset = len;
    if ( (A.unspents_offset & 3) != 0 )
        A.unspents_offset += 4 - (A.unspents_offset & 3);
    if ( A.unspents_offset > sizeof(A.coinaddr) )
        printf("overflowed unspentinds[] with unspentoffset.%d for (%s)\n",A.unspents_offset,coinaddr);
    if ( Debuglevel > 2 )
        printf("maxunspents.%ld\n",(sizeof(A.coinaddr) - A.unspents_offset) / sizeof(uint32_t));
    return(coin777_RWmmap(1 | COIN777_SHA256,&A,coin,&coin->addrinfos,addrind));
}

void coin777_Qunspent(struct coin777 *coin,uint32_t addrind,struct coin777_addrinfo *addrinfo,uint32_t unspentind,int32_t numunspents)
{
    uint32_t addrtx[2];
    //struct Qactives *actives;
    //actives = tmpalloc(coin->name,&coin->tmpMEM,sizeof(*actives));
    //actives->unspentind = unspentind, actives->addrtx[0] = addrind, actives->addrtx[1] = numunspents;
    update_sha256(coin->actives.sha256,&coin->actives.state,(uint8_t *)addrtx,sizeof(addrtx));
    //queue_enqueue("actives",&coin->actives.writeQ,&actives->DL);
    addrtx[0] = addrind, addrtx[1] = numunspents;
    coin777_addDB(coin,coin->DBs.transactions,coin->actives.DB,addrtx,sizeof(addrtx),&unspentind,sizeof(unspentind));
}

void coin777_addspend(struct coin777 *coin,uint32_t totalspends,uint32_t addrind,uint32_t unspentind,uint64_t value,uint32_t spending_txidind,uint16_t vin)
{
    struct coin777_addrinfo A; uint32_t *unspents;
    if ( coin777_RWmmap(0,&A,coin,&coin->addrinfos,addrind) == 0 )
    {
        A.balance -= value;
        unspentind |= (1 << 31);
        if ( A.numunspents < (sizeof(A.coinaddr) - A.unspents_offset) / sizeof(uint32_t) )
        {
            unspents = (uint32_t *)&A.coinaddr[A.unspents_offset];
            unspents[A.numunspents] = unspentind;
        }
        else coin777_Qunspent(coin,addrind,&A,unspentind,A.numunspents);
        A.numunspents++;
        coin777_RWmmap(1 | COIN777_SHA256,&A,coin,&coin->addrinfos,addrind);
    }
    coin777_RWmmap(1 | COIN777_SHA256,&unspentind,coin,&coin->spends,totalspends);
}

void coin777_addunspent(struct coin777 *coin,uint32_t addrind,uint32_t scriptind,uint64_t value,uint32_t unspentind)
{
    struct coin777_addrinfo A; struct unspent_info U;
    if ( coin777_RWmmap(0,&U,coin,&coin->unspents,unspentind) == 0 )
    {
        U.value = value, U.addrind = addrind;
        coin777_RWmmap(1 | COIN777_SHA256,&U,coin,&coin->unspents,unspentind);
    }
    if ( coin777_RWmmap(0,&A,coin,&coin->addrinfos,addrind) == 0 )
    {
        A.balance += value;
        //printf("balance %.8f <- %.8f\n",dstr(A.balance),dstr(value));
        if ( A.numunspents < ((sizeof(A.coinaddr) - A.unspents_offset) / sizeof(uint32_t)) )
            ((uint32_t *)&A.coinaddr[A.unspents_offset])[(long)A.numunspents] = unspentind;
        else coin777_Qunspent(coin,addrind,&A,unspentind,A.numunspents);
        A.numunspents++;
        coin777_RWmmap(1 | COIN777_SHA256,&A,coin,&coin->addrinfos,addrind);
    }
}

int32_t coin777_script0(struct coin777 *coin,uint32_t addrind,uint8_t *script,int32_t scriptlen)
{
    struct coin777_addrinfo A;
    if ( coin777_RWmmap(0,&A,coin,&coin->addrinfos,addrind) == 0 && A.scriptlen == scriptlen )
        return(memcmp(script,&A.coinaddr[A.addrlen],scriptlen));
    return(-1);
}

int32_t coin777_addblock(void *state,uint32_t blocknum,char *blockhashstr,char *merklerootstr,uint32_t timestamp,uint64_t minted,uint32_t txidind,uint32_t unspentind,uint32_t numspends,uint32_t addrind,uint32_t scriptind,uint64_t total,uint64_t spent)
{
    bits256 blockhash,merkleroot; struct coin777 *coin = state; struct coin_offsets zeroB,B,block; int32_t err = 0;
    memset(&B,0,sizeof(B));
   // Debuglevel = 3;
    if ( Debuglevel > 2 )
        printf("B.%u T.%u U.%u S.%u A.%u C.%u\n",blocknum,txidind,unspentind,numspends,addrind,scriptind);
    if ( blockhashstr != 0 ) // start of block
    {
        memset(blockhash.bytes,0,sizeof(blockhash)), decode_hex(blockhash.bytes,sizeof(blockhash),blockhashstr);
        memset(merkleroot.bytes,0,sizeof(merkleroot)), decode_hex(merkleroot.bytes,sizeof(merkleroot),merklerootstr);
        B.blockhash = blockhash, B.merkleroot = merkleroot;
    } // else end of block, but called with blocknum+1
    B.timestamp = timestamp, B.txidind = txidind, B.unspentind = unspentind, B.numspends = numspends, B.addrind = addrind, B.scriptind = scriptind;
    B.total = total, B.spent = spent;
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
                if ( block.total != 0 && B.total != 0 && B.total != block.total )
                    err = -8, printf("nonz total %.8f overwrites %.8f\n",dstr(B.total),dstr(block.total));
                if ( block.spent != 0 && B.spent != 0 && B.spent != block.spent )
                    err = -9, printf("nonz spent %.8f overwrites %.8f\n",dstr(B.spent),dstr(block.spent));
            }
        }
        coin->latest = B, coin->latestblocknum = blocknum;
        if ( coin777_RWmmap(1 | (blockhashstr != 0)*COIN777_SHA256,&B,coin,&coin->blocks,blocknum) != 0 )
            return(-1);
    }
    return(err);
}

uint32_t coin777_findind(struct coin777 *coin,struct coin777_state *sp,uint8_t *data,int32_t datalen)
{
    struct hashed_uint32 *entry; extern int32_t Duplicate;
    HASH_FIND(hh,(struct hashed_uint32 *)sp->table,data,datalen,entry);
    /*if ( entry == 0 )
     {
     coin777_processQs(coin);
     HASH_FIND(hh,(struct hashed_uint32 *)sp->table,data,datalen,entry);
     }*/
    if ( entry != 0 )
    {
        Duplicate++;
        return(entry->ind);
    }
    return(0);
}

void coin777_addind(struct coin777 *coin,struct coin777_state *sp,void *data,int32_t datalen,uint32_t ind,struct queueitem *item)
{
    struct hashed_uint32 *entry,*table;
    if ( item != 0 )
    {
        update_sha256(sp->sha256,&sp->state,data,datalen);
        // queue_enqueue(sp->name,&sp->writeQ,item);
        coin777_addDB(coin,coin->DBs.transactions,sp->DB,&ind,sizeof(ind),data,datalen);
    }
    entry = tmpalloc(coin->name,&coin->tmpMEM,sizeof(*entry)), entry->ind = ind;
    table = sp->table; HASH_ADD_KEYPTR(hh,table,data,datalen,entry); sp->table = table;
}

int32_t coin777_addvout(void *state,uint32_t txidind,uint16_t vout,uint32_t unspentind,char *coinaddr,char *scriptstr,uint64_t value,uint32_t *addrindp,uint32_t *scriptindp)
{
    struct coin777 *coin = state; uint32_t *ptr,addrind,scriptind = 0; int32_t tmp,len,scriptlen; uint8_t script[4096],*scriptptr,*addrptr;
    struct Qaddr *addritem = 0; struct Qscript *scriptitem = 0;
    coin->credits += value;
    scriptlen = (int32_t)strlen(scriptstr) >> 1, decode_hex(script,scriptlen,scriptstr);
    len = (int32_t)strlen(coinaddr) + 1;
    if ( (addrind= coin777_findind(coin,&coin->addrs,(uint8_t *)coinaddr,len)) == 0 )
    {
        tmp = sizeof(addrind);
        if ( (ptr= db777_get(&addrind,&tmp,coin->DBs.transactions,coin->addrs.DB,coinaddr,len)) == 0 || addrind == 0 || tmp != sizeof(*ptr) )
        {
            addrind = (*addrindp)++;
            coin777_createaddr(coin,addrind,coinaddr,len,script,scriptlen);
            addritem = tmpalloc(coin->name,&coin->tmpMEM,sizeof(*addritem) + len + 1), addritem->addrind = addrind, strcpy(addritem->coinaddr,coinaddr);
        }
        addrptr = tmpalloc(coin->name,&coin->tmpMEM,len), memcpy(addrptr,coinaddr,len);
        coin777_addind(coin,&coin->addrs,addrptr,len,addrind,&addritem->DL);
    }
    else if ( coin777_script0(coin,addrind,script,scriptlen) != 0 )
    {
        if ( (scriptind= coin777_findind(coin,&coin->scripts,script,scriptlen)) == 0 )
        {
            tmp = sizeof(scriptind);
            if ( (ptr= db777_get(&scriptind,&tmp,coin->DBs.transactions,coin->scripts.DB,script,scriptlen)) == 0 || scriptind == 0 || tmp != sizeof(*ptr) )
            {
                scriptind = (*scriptindp)++;
                scriptitem = tmpalloc(coin->name,&coin->tmpMEM,sizeof(*scriptitem) + scriptlen), scriptitem->scriptind = scriptind, scriptitem->scriptlen = scriptlen, memcpy(scriptitem->script,script,scriptlen);
            }
            scriptptr = tmpalloc(coin->name,&coin->tmpMEM,scriptlen), memcpy(scriptptr,script,scriptlen);
            coin777_addind(coin,&coin->scripts,scriptptr,scriptlen,scriptind,&scriptitem->DL);
         }
    }
    if ( Debuglevel > 2 )
        printf("UNSPENT.%u addrind.%u T%u vo%-3d U%u %.8f %s %llx\n",unspentind,addrind,txidind,vout,unspentind,dstr(value),coinaddr,*(long long *)script);
    coin777_addunspent(coin,addrind,scriptind,value,unspentind);
    return(0);
}

uint64_t coin777_addvin(void *state,uint32_t txidind,uint16_t vin,uint32_t totalspends,char *spent_txidstr,uint16_t spent_vout)
{
    struct coin777 *coin = state; bits256 txid; int32_t tmp; uint32_t *ptr,spent_txidind,txoffsets[2],unspentind = 0; struct unspent_info U;
    if ( Debuglevel > 2 )
        printf("SPEND T%u vi%-3d S%u %s vout.%d\n",txidind,vin,totalspends,spent_txidstr,spent_vout);
    memset(txid.bytes,0,sizeof(txid)), decode_hex(txid.bytes,sizeof(txid),spent_txidstr);
    if ( (spent_txidind= coin777_findind(coin,&coin->txids,txid.bytes,sizeof(txid))) == 0 )
    {
        tmp = sizeof(spent_txidind);
        if ( (ptr= db777_get(&spent_txidind,&tmp,coin->DBs.transactions,coin->txids.DB,txid.bytes,sizeof(txid))) == 0 || txidind == 0 || tmp != sizeof(*ptr) )
        {
            printf("cant find txid.(%s) spendvout.%d from \n",spent_txidstr,spent_vout), debugstop();
            return(-1);
        }
    }
    if ( spent_txidind > txidind )
    {
        printf("coin777_addvin txidind overflow? spent_txidind.%u vs max.%u\n",spent_txidind,txidind), debugstop();
        return(-2);
    }
    if ( coin777_RWmmap(0,txoffsets,coin,&coin->txoffsets,spent_txidind) == 0  )
    {
        unspentind = txoffsets[0] + spent_vout;
        if ( coin777_RWmmap(0,&U,coin,&coin->unspents,unspentind) == 0 )
        {
            if ( U.spending_txidind != 0 && U.spending_txidind != txidind )
                printf("unspentind.%u interloper txidind.%u overwrites.%u\n",unspentind,txidind,U.spending_txidind);
            if ( txidind != U.spending_txidind )
                U.spending_txidind = txidind;
            if ( vin != U.spending_vin )
                U.spending_vin = vin;
            if ( U.value == 0 || U.addrind == 0 )
                printf("strange unspent.%u for addrind.%u %.8f\n",unspentind,U.addrind,dstr(U.value));
            coin777_addspend(coin,totalspends,U.addrind,unspentind,U.value,txidind,vin);
            coin->debits += U.value;
            coin777_RWmmap(1 | COIN777_SHA256,&U,coin,&coin->unspents,unspentind);
            return(U.value);
        } else printf("error getting unspents[%u]\n",unspentind);
    } else printf("error getting txoffsets for unspentind.%u spent_txidind.%u\n",unspentind,spent_txidind);
    return(0);
}

int32_t coin777_addtx(void *state,uint32_t blocknum,uint32_t txidind,char *txidstr,uint32_t firstvout,uint16_t numvouts,uint64_t total,uint32_t firstvin,uint16_t numvins)
{
    struct coin777 *coin = state; bits256 txid,*txptr; uint32_t txoffsets[2]; struct Qtx *txitem;
    memset(txid.bytes,0,sizeof(txid)), decode_hex(txid.bytes,sizeof(txid),txidstr);
    coin777_RWmmap(1 | COIN777_SHA256,&txid,coin,&coin->txidbits,txidind);
    if ( Debuglevel > 2 )
        printf("ADDTX.%s: %x T%u U%u + numvouts.%d, S%u + numvins.%d\n",txidstr,*(int *)txid.bytes,txidind,firstvout,numvouts,firstvin,numvins);
    txoffsets[0] = firstvout, txoffsets[1] = firstvin, coin777_RWmmap(1 | COIN777_SHA256,txoffsets,coin,&coin->txoffsets,txidind);
    txoffsets[0] += numvouts, txoffsets[1] += numvins, coin777_RWmmap(1 | COIN777_SHA256,txoffsets,coin,&coin->txoffsets,txidind+1);
    txitem = tmpalloc(coin->name,&coin->tmpMEM,sizeof(*txitem)), txitem->txid = txid, txitem->txidind = txidind;
    txptr = tmpalloc(coin->name,&coin->tmpMEM,sizeof(*txptr)), *txptr = txid;
    coin777_addind(coin,&coin->txids,txptr,sizeof(txid),txidind,&txitem->DL);
    return(0);
}

/*int32_t coin777_processQs(struct coin777 *coin)
{
    struct Qtx *tx; struct Qaddr *addr; struct Qscript *script; struct Qactives *actives; int32_t n = 0;
    if ( coin == 0 )
        return(0);
    while ( (tx= queue_dequeue(&coin->txids.writeQ,0)) != 0 )
    {
        if ( Debuglevel > 2 )
            printf("permanently store %llx -> txidind.%u\n",(long long)tx->txid.txid,tx->txidind);
        coin777_addDB(coin,coin->DBs.transactions,coin->txids.DB,tx->txid.bytes,sizeof(tx->txid),&tx->txidind,sizeof(tx->txidind));
        //free(tx);
        n++;
    }
    while ( (addr= queue_dequeue(&coin->addrs.writeQ,0)) != 0 )
    {
        if ( Debuglevel > 2 )
            printf("permanently store (%s) -> addrind.%u\n",addr->coinaddr,addr->addrind);
        coin777_addDB(coin,coin->DBs.transactions,coin->addrs.DB,addr->coinaddr,(int32_t)strlen(addr->coinaddr)+1,&addr->addrind,sizeof(addr->addrind));
        //free(addr);
        n++;
    }
    while ( (script= queue_dequeue(&coin->scripts.writeQ,0)) != 0 )
    {
        //if ( Debuglevel > 2 )
            printf("permanently store (%llx) -> scriptind.%u addrind.%u\n",*(long long *)script->script,script->scriptind,coin->latest.addrind);
        coin777_addDB(coin,coin->DBs.transactions,coin->scripts.DB,script->script,script->scriptlen,&script->scriptind,sizeof(script->scriptind));
        //free(script);
        n++;
    }
    while ( (actives= queue_dequeue(&coin->actives.writeQ,0)) != 0 )
    {
        coin777_addDB(coin,coin->DBs.transactions,coin->actives.DB,actives->addrtx,sizeof(actives->addrtx),&actives->unspentind,sizeof(actives->unspentind));
        //free(actives);
        n++;
    }
    return(n);
}*/

int32_t coin777_getinds(void *state,uint32_t blocknum,uint32_t *timestampp,uint32_t *txidindp,uint32_t *unspentindp,uint32_t *numspendsp,uint32_t *addrindp,uint32_t *scriptindp)
{
    struct coin777 *coin = state; struct coin_offsets *block = coin->blocks.table;
    if ( block == 0 || blocknum >= coin->blocks.maxitems )
    {
        printf("coin777_getinds offsets overflow? %p blocknum.%u vs max.%u\n",block,blocknum,coin->blocks.maxitems);
        return(-1);
    }
    block = &block[blocknum];
    if ( blocknum == 0 )
        *txidindp = *unspentindp = *numspendsp = *addrindp = *scriptindp = 1, *timestampp = 0;
    else
    {
        *timestampp = block->timestamp, *txidindp = block->txidind, *unspentindp = block->unspentind, *numspendsp = block->numspends, *addrindp = block->addrind, *scriptindp = block->scriptind;
    }
    return(0);
}

uint64_t addrinfos_sum(struct coin777 *coin,uint32_t addrind)
{
    struct coin777_addrinfo A; uint64_t sum = 0; int32_t i;
    for (i=0; i<=addrind; i++)
    {
        if ( coin777_RWmmap(0,&A,coin,&coin->addrinfos,addrind) == 0 )
        {
            sum += A.balance;//, printf("%.8f ",dstr(addrinfos[i].balance));
            //printf("-> sum %.8f addrind.%d maxinds.%d\n",dstr(sum),addrind,coin->addrs.maxitems);
            coin->addrsum = sum;
        }
    }
    return(sum);
}

uint64_t coin777_permsize(struct coin777 *coin)
{
    return(coin->totalsize);
}

int32_t coin777_sync(struct coin777 *coin)
{
    if ( coin != 0 )
    {
        printf("Sync.%s\n",coin->name);
        //coin777_processQs(coin);
        db777_sync(coin->DBs.transactions,&coin->DBs,DB777_FLUSH);
        sync_mappedptr(&coin->blocks.M,0);
        sync_mappedptr(&coin->txoffsets.M,0);
        sync_mappedptr(&coin->txidbits.M,0);
        sync_mappedptr(&coin->unspents.M,0);
        sync_mappedptr(&coin->addrinfos.M,0);
        sync_mappedptr(&coin->spends.M,0);
    }
    return(0);
}

uint64_t coin777_ledgerhash(struct coin777 *coin,uint32_t blocknum,int32_t numsyncs)
{
    int32_t i,retval = 0; struct coin777_hashes H; bits256 hashbits;
    memset(&H,0,sizeof(H)); H.blocknum = blocknum, H.numsyncs = numsyncs;
    for (i=0; i<coin->num; i++)
    {
        H.states[i] = coin->sps[i]->state;
        memcpy(H.sha256[i],coin->sps[i]->sha256,sizeof(H.sha256[i]));
    }
    calc_sha256(0,hashbits.bytes,(uint8_t *)(void *)((long)&H + sizeof(H.ledgerhash)),sizeof(H) - sizeof(H.ledgerhash));
    H.ledgerhash = hashbits.txid;
    if ( numsyncs < 0 )
    {
        for (i=0; i<coin->num; i++)
            printf("%08x ",*(int *)H.sha256[i]);
    }
    if ( numsyncs >= 0 )
    {
        printf("SYNCNUM.%d -> %d supply %.8f | ledgerhash %08x\n",numsyncs,blocknum,dstr(coin->credits)-dstr(coin->debits),(uint32_t)hashbits.txid);
        if ( db777_set(DB777_HDD,coin->DBs.transactions,coin->hashes.DB,&numsyncs,sizeof(numsyncs),&H,sizeof(H)) != 0 )
            printf("error saving ledger\n");
        if ( numsyncs > 0 )
        {
            numsyncs = 0;
            if ( (retval = db777_set(DB777_HDD,coin->DBs.transactions,coin->hashes.DB,&numsyncs,sizeof(numsyncs),&H,sizeof(H))) != 0 )
                printf("error saving numsyncs.0 retval.%d\n",retval);
        }
    }
    return((uint32_t)H.ledgerhash);
}

int32_t coin777_parse(struct coin777 *coin,uint32_t RTblocknum,int32_t syncflag,int32_t minconfirms)
{
    uint32_t blocknum,dispflag,ledgerhash=0,allocsize,timestamp,txidind,numrawvouts,numrawvins,addrind,scriptind; int32_t numtx;
    uint64_t origsize,supply,oldsupply; double estimate,elapsed,startmilli;
    blocknum = coin->blocknum;
    if ( blocknum <= (RTblocknum - minconfirms) )
    {
        startmilli = milliseconds();
        dispflag = 1 || (blocknum > RTblocknum - 1000);
        dispflag += ((blocknum % 100) == 0);
        oldsupply = (coin->credits - coin->debits), origsize = coin777_permsize(coin);
        if ( coin->DBs.transactions == 0 )
            coin->DBs.transactions = sp_begin(coin->DBs.env), coin->numsyncs++;
        if ( coin777_getinds(coin,blocknum,&timestamp,&txidind,&numrawvouts,&numrawvins,&addrind,&scriptind) == 0 )
        {
            numtx = parse_block(coin,&txidind,&numrawvouts,&numrawvins,&addrind,&scriptind,coin->name,coin->serverport,coin->userpass,blocknum,coin777_addblock,coin777_addvin,coin777_addvout,coin777_addtx);
            if ( syncflag != 0 )
            {
                coin->addrsum = addrinfos_sum(coin,addrind);
                ledgerhash = (uint32_t)coin777_ledgerhash(coin,blocknum,coin->numsyncs);
                coin777_sync(coin);
                coin->DBs.transactions = 0;
            }
            else ledgerhash = (uint32_t)coin777_ledgerhash(coin,blocknum,-1);
            dxblend(&coin->calc_elapsed,(milliseconds() - startmilli),.99);
            allocsize = (uint32_t)(coin777_permsize(coin) - origsize);
            estimate = estimate_completion(coin->startmilli,blocknum - coin->startblocknum,RTblocknum-blocknum)/60000;
            elapsed = (milliseconds() - coin->startmilli)/60000.;
            supply = (coin->credits - coin->debits);
            if ( dispflag != 0 )
            {
                extern int32_t Duplicate,Mismatch,Added,Linked,Numgets;
                printf("%.3f %-5s [lag %-5d] %-6u %.8f %.8f (%.8f) [%.8f] %13.8f | dur %.2f %.2f %.2f | len.%-5d %s %.1f | H%d E%d R%d W%d %08x\n",coin->calc_elapsed/1000.,coin->name,RTblocknum-blocknum,blocknum,dstr(supply),dstr(coin->addrsum),dstr(supply)-dstr(coin->addrsum),dstr(supply)-dstr(oldsupply),dstr(coin->minted != 0 ? coin->minted : coin->latest.total),elapsed,elapsed+(RTblocknum-blocknum)*coin->calc_elapsed/60000,elapsed+estimate,allocsize,_mbstr(coin->totalsize),(double)coin->totalsize/blocknum,Duplicate,Mismatch,Numgets,Added,ledgerhash);
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

#endif
#endif
