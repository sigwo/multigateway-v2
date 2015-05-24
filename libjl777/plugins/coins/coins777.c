//
//  coins777.c
//  crypto777
//
//  Created by James on 4/9/15.
//  Copyright (c) 2015 jl777. All rights reserved.
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
    queue_t writeQ;
    void *table;
    uint32_t maxitems,itemsize;
};

struct coin_offsets { bits256 blockhash,merkleroot; uint64_t total,spent; uint32_t timestamp,txidind,unspentind,numspends,addrind,scriptind; };
struct unspent_info { uint64_t value; uint32_t addrind,spending_txidind; uint16_t spending_vin; };
struct hashed_uint32 { UT_hash_handle hh; uint32_t ind; };

struct coin777_addrinfo
{
    uint64_t balance;
    uint32_t firstblocknum,numunspents:28,notify:1,pending:1,MGW:1,dirty:1;
    uint16_t scriptlen;
    uint8_t addrlen,unspents_offset;
    char coinaddr[128 - 16];
};

struct Qtx { struct queueitem DL; bits256 txid; uint32_t txidind; };
struct Qaddr { struct queueitem DL; uint32_t addrind; char coinaddr[]; };
struct Qscript { struct queueitem DL; uint32_t scriptind; uint16_t scriptlen; char script[]; };

struct coin777
{
    char name[16],serverport[64],userpass[128],*jsonstr;
    cJSON *argjson;
    double lastgetinfo;
    struct ramchain ramchain;
    int32_t use_addmultisig,minconfirms;
    struct packed_info P;
    
    uint32_t latestblocknum; struct coin_offsets latest;
    struct env777 DBs;  struct coin777_state txids,addrs,scripts,blocks,txoffsets,txidbits,unspents,spends,addrinfos;
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

int32_t coin777_parse(void *state,struct coin777 *coin,uint32_t blocknum);
int32_t coin777_processQs(struct coin777 *coin);
uint64_t coin777_permsize(void *state);
void coin777_ensurespace(struct coin777 *coin,uint32_t blocknum,uint32_t txidind,uint32_t addrind,uint32_t scriptind,uint32_t unspentind,uint32_t totalspends);

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
    char coinaddr[8192],script[8192]; cJSON *item; uint64_t value,total = 0; int32_t i,numvouts;
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
    char txidstr[8192],coinbase[8192]; cJSON *item; int32_t i,numvins; uint64_t value,total = 0;
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
                    return(0);
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
    //printf("BLOCK.%d: block.%d numtx.%d minted %.8f rawnumvins.%d rawnumvouts.%d\n",blocknum,raw->blocknum,raw->numtx,dstr(raw->minted),raw->numrawvins,raw->numrawvouts);
    return(numtx);
}

void coin777_stateinit(struct env777 *DBs,struct coin777_state *sp,char *coinstr,char *subdir,char *name,char *compression,int32_t flags,int32_t valuesize)
{
    safecopy(sp->name,name,sizeof(sp->name));
    if ( DBs != 0 )
    {
        safecopy(DBs->coinstr,coinstr,sizeof(DBs->coinstr));
        safecopy(DBs->subdir,subdir,sizeof(DBs->subdir));
    }
    update_sha256(sp->sha256,&sp->state,0,0);
    sp->itemsize = valuesize;
    if ( DBs != 0 )
        sp->DB = db777_open(0,DBs,name,compression,flags,valuesize);
}

void *coin777_ensure(struct coin777 *coin,struct coin777_state *sp,uint32_t ind)
{
    char fname[1024]; long needed; int32_t rwflag = 1;
    needed = ind * sp->itemsize;
    sprintf(fname,"DB"), ensure_directory(fname), strcat(fname,"/"), strcat(fname,coin->name), ensure_directory(fname), strcat(fname,"/"), strcat(fname,sp->name);
    //printf("%s.(%d %d)\n",sp->name,ind,sp->itemsize);
    if ( needed > sp->M.allocsize )
    {
        if ( sp->M.fileptr != 0 )
            release_map_file(sp->M.fileptr,sp->M.allocsize), sp->M.fileptr = 0;
        ensure_filesize(fname,needed);
    }
    if ( sp->M.fileptr == 0 )
    {
        if ( init_mappedptr(&sp->MEM.ptr,&sp->M,0,rwflag,fname) != 0 )
            sp->MEM.size = sp->M.allocsize;
    }
    if ( (sp->table= sp->M.fileptr) == 0 )
        printf("couldnt map %s\n",fname);
    return(sp->table);
}

void coin777_ensurespace(struct coin777 *coin,uint32_t blocknum,uint32_t txidind,uint32_t addrind,uint32_t scriptind,uint32_t unspentind,uint32_t totalspends)
{
    char *subdir="",*coinstr = coin->name;
    if ( coin->addrs.DB == 0 )
        coin777_stateinit(&coin->DBs,&coin->addrs,coinstr,subdir,"addrs","zstd",DB777_HDD,sizeof(uint32_t));
    if ( coin->scripts.DB == 0 )
        coin777_stateinit(&coin->DBs,&coin->scripts,coinstr,subdir,"scripts","zstd",DB777_HDD,sizeof(uint32_t));
    if ( coin->txids.DB == 0 )
    {
        coin777_stateinit(&coin->DBs,&coin->txids,coinstr,subdir,"txids",0,DB777_HDD,sizeof(uint32_t));
        env777_start(0,&coin->DBs,0);
    }
    if ( coin->blocks.table == 0 )
        coin777_stateinit(0,&coin->blocks,coinstr,subdir,"blocks","zstd",0,sizeof(struct coin_offsets));
    if ( coin->txoffsets.table == 0 )
        coin777_stateinit(0,&coin->txoffsets,coinstr,subdir,"txoffsets","zstd",0,sizeof(uint32_t) * 2);
    if ( coin->txidbits.table == 0 )
        coin777_stateinit(0,&coin->txidbits,coinstr,subdir,"txidbits",0,0,sizeof(bits256));
    if ( coin->unspents.table == 0 )
        coin777_stateinit(0,&coin->unspents,coinstr,subdir,"unspents","zstd",0,sizeof(struct unspent_info));
    if ( coin->spends.table == 0 )
        coin777_stateinit(0,&coin->spends,coinstr,subdir,"spends","zstd",0,sizeof(uint32_t));
    if ( coin->addrinfos.table == 0 )
        coin777_stateinit(0,&coin->addrinfos,coinstr,subdir,"addrinfos","zstd",0,sizeof(struct coin777_addrinfo));
    coin->blocks.table = coin777_ensure(coin,&coin->blocks,blocknum);
    coin->txoffsets.table = coin777_ensure(coin,&coin->txoffsets,txidind);
    coin->txidbits.table = coin777_ensure(coin,&coin->txidbits,txidind);
    coin->unspents.table = coin777_ensure(coin,&coin->unspents,unspentind);
    coin->addrinfos.table = coin777_ensure(coin,&coin->addrinfos,addrind);
    coin->spends.table = coin777_ensure(coin,&coin->spends,totalspends);
}

void *coin777_itemptr(struct coin777 *coin,struct coin777_state *sp,uint32_t ind)
{
    void *ptr = sp->table;
    if ( ptr == 0 || ind >= sp->maxitems )
    {
        printf("%s addrinfos overflow? %p addrind.%u vs max.%u\n",sp->name,ptr,ind,sp->maxitems);
        return(0);
    }
    return((void *)((long)ptr + sp->itemsize*ind));
}

uint32_t coin777_findind(struct coin777 *coin,struct coin777_state *sp,uint8_t *data,int32_t datalen)
{
    struct hashed_uint32 *entry;
    HASH_FIND(hh,(struct hashed_uint32 *)sp->table,data,datalen,entry);
    if ( entry != 0 )
        return(entry->ind);
    return(0);
}

void coin777_addind(struct coin777 *coin,struct coin777_state *sp,void *data,int32_t datalen,uint32_t ind,struct queueitem *item)
{
    struct hashed_uint32 *entry,*table;
    entry = tmpalloc(coin->name,&coin->tmpMEM,sizeof(*entry)), entry->ind = ind;
    table = coin->addrs.table; HASH_ADD_KEYPTR(hh,table,data,datalen,entry); coin->addrs.table = table;
    if ( item != 0 )
    {
        update_sha256(sp->sha256,&sp->state,data,datalen);
        queue_enqueue(sp->name,&sp->writeQ,item);
    }
}

struct coin777_addrinfo *coin777_createaddr(struct coin777 *coin,uint32_t addrind,char *coinaddr,int32_t len,uint8_t *script,uint16_t scriptlen)
{
    struct coin777_addrinfo *addrinfo;
    if ( (addrinfo= coin777_itemptr(coin,&coin->addrinfos,addrind)) != 0 )
    {
        addrinfo->addrlen = len;
        addrinfo->scriptlen = scriptlen;
        memcpy(addrinfo->coinaddr,coinaddr,len);
        memcpy(&addrinfo->coinaddr[len],script,scriptlen), len += scriptlen;
        addrinfo->unspents_offset = len;
        if ( (addrinfo->unspents_offset & 3) != 0 )
            addrinfo->unspents_offset += 4 - (addrinfo->unspents_offset & 3);
        if ( addrinfo->unspents_offset > sizeof(addrinfo->coinaddr) )
            printf("overflowed unspentinds[] with unspentoffset.%d for (%s)\n",addrinfo->unspents_offset,coinaddr);
        printf("maxunspents.%ld\n",(sizeof(addrinfo->coinaddr) - addrinfo->unspents_offset) / sizeof(uint32_t));
    }
    return(addrinfo);
}

void coin777_addspend(struct coin777 *coin,uint32_t totalspends,uint32_t addrind,uint32_t unspentind,uint64_t value,uint32_t spending_txidind,uint16_t vin)
{
    struct coin777_addrinfo *addrinfo; int32_t i,flag = 0; uint32_t *unspents,*spend,checkind;
    if ( (addrinfo= coin777_itemptr(coin,&coin->addrinfos,addrind)) != 0 )
    {
        addrinfo->balance -= value;
        unspents = (uint32_t *)&addrinfo->coinaddr[addrinfo->unspents_offset];
        for (i=0; i<addrinfo->numunspents; i++)
            if ( unspents[i] == unspentind )
            {
                unspents[i] |= (1 << 31);
                flag = 1;
                break;
            }
        if ( flag == 0 )
        {
            FILE *fp; char fname[1024];
            sprintf(fname,"DB/%s/actives/%s",coin->name,addrinfo->coinaddr);
            os_compatible_path(fname);
            if ( (fp= fopen(fname,"rb+")) != 0 )
            {
                while ( fread(&checkind,1,sizeof(checkind),fp) == sizeof(checkind) )
                    if ( checkind == unspentind )
                    {
                        checkind |= (1 << 31);
                        fseek(fp,-sizeof(unspentind),SEEK_CUR);
                        fwrite(&checkind,1,sizeof(checkind),fp);
                        flag = 1;
                        break;
                    }
                fclose(fp);
            }
            if ( flag == 0 )
                printf("couldnt find unspentind.%u %.8f for %s from numunspents.%d of max.%ld\n",unspentind,dstr(value),addrinfo->coinaddr,addrinfo->numunspents,(sizeof(addrinfo->coinaddr) - addrinfo->unspents_offset) / sizeof(uint32_t));
        }
    }
    if ( (spend= coin777_itemptr(coin,&coin->spends,totalspends)) != 0 )
        *spend = unspentind;
    update_sha256(coin->spends.sha256,&coin->spends.state,(uint8_t *)&unspentind,sizeof(unspentind));
}

void coin777_addunspent(struct coin777 *coin,struct unspent_info *U,uint32_t addrind,uint32_t scriptind,uint64_t value,uint32_t unspentind)
{
    struct coin777_addrinfo *addrinfo; FILE *fp; char fname[1024];
    U->value = value, U->addrind = addrind;
    if ( (addrinfo= coin777_itemptr(coin,&coin->addrinfos,addrind)) != 0 )
    {
        addrinfo->balance += value;
        if ( addrinfo->numunspents < ((sizeof(addrinfo->coinaddr) - addrinfo->unspents_offset) / sizeof(uint32_t)) )
            ((uint32_t *)&addrinfo->coinaddr[addrinfo->unspents_offset])[(long)addrinfo->numunspents] = unspentind;
        else
        {
            sprintf(fname,"DB/%s/actives/%s",coin->name,addrinfo->coinaddr);
            os_compatible_path(fname);
            if ( (fp= fopen(fname,"ab+")) != 0 )
                fwrite(&unspentind,1,sizeof(unspentind),fp), fclose(fp);
        }
        addrinfo->numunspents++;
    }
    update_sha256(coin->unspents.sha256,&coin->unspents.state,(uint8_t *)U,sizeof(*U));
}

int32_t coin777_script0(struct coin777 *coin,uint32_t addrind,uint8_t *script,int32_t scriptlen)
{
    struct coin777_addrinfo *addrinfo;
    if ( (addrinfo= coin777_itemptr(coin,&coin->addrinfos,addrind)) != 0 && addrinfo->scriptlen == scriptlen )
        return(memcmp(script,&addrinfo->coinaddr[addrinfo->addrlen],scriptlen));
    return(-1);
}

int32_t coin777_addblock(void *state,uint32_t blocknum,char *blockhashstr,char *merklerootstr,uint32_t timestamp,uint64_t minted,uint32_t txidind,uint32_t unspentind,uint32_t numspends,uint32_t addrind,uint32_t scriptind,uint64_t total,uint64_t spent)
{
    bits256 blockhash,merkleroot; struct coin777 *coin = state; struct coin_offsets checkO,O,*block; int32_t err = 0;
    if ( (block= coin777_itemptr(coin,&coin->blocks,blocknum)) == 0  )
    {
        printf("coin blocks overflow? %p blocknum.%u vs max.%u\n",block,blocknum,coin->blocks.maxitems);
        return(-1);
    }
    if ( blockhashstr == 0 )
        printf("end block");
    else
    {
        printf("    block");
        decode_hex(blockhash.bytes,sizeof(blockhash),blockhashstr);
        decode_hex(merkleroot.bytes,sizeof(merkleroot),merklerootstr);
        block->blockhash = blockhash, block->merkleroot = merkleroot;
        coin777_ensurespace(coin,blocknum+4096,txidind+65536,addrind+65536,scriptind+65536,unspentind+65536,numspends+65536);
    }
    printf(" B%u t%d T%u U%u S%u A%u F%u\n",blocknum,timestamp,txidind,unspentind,numspends,addrind,scriptind);
    O = *block;
    block->timestamp = timestamp, block->txidind = txidind, block->unspentind = unspentind, block->numspends = numspends, block->addrind = addrind, block->scriptind = scriptind;
    memset(&checkO,0,sizeof(checkO));
    if ( memcmp(&O,&checkO,sizeof(checkO)) != 0 )
    {
        if ( O.timestamp != block->timestamp )
            err = -2, printf("nonz timestamp.%u overwritten by %u\n",O.timestamp,block->timestamp);
        if ( O.txidind != block->txidind )
            err = -3, printf("nonz txidind.%u overwritten by %u\n",O.txidind,block->txidind);
        if ( O.unspentind != block->unspentind )
            err = -4, printf("nonz unspentind.%u overwritten by %u\n",O.unspentind,block->unspentind);
        if ( O.numspends != block->numspends )
            err = -5, printf("nonz numspends.%u overwritten by %u\n",O.numspends,block->numspends);
        if ( O.addrind != block->addrind )
            err = -6, printf("nonz addrind.%u overwritten by %u\n",O.addrind,block->addrind);
        if ( O.scriptind != block->scriptind )
            err = -7, printf("nonz scriptind.%u overwritten by %u\n",O.scriptind,block->scriptind);
        if ( O.total != block->total && block->total != 0 )
            err = -8, printf("nonz total %.8f overwritten by %.8f\n",dstr(O.total),dstr(block->total));
        if ( O.spent != block->spent && block->spent != 0 )
            err = -9, printf("nonz spent %.8f overwritten by %.8f\n",dstr(O.spent),dstr(block->spent));
    }
    coin->latest = *block, coin->latestblocknum = blocknum;
    update_sha256(coin->blocks.sha256,&coin->blocks.state,(uint8_t *)block,sizeof(*block));
    return(err);
}

int32_t coin777_addvout(void *state,uint32_t txidind,uint16_t vout,uint32_t unspentind,char *coinaddr,char *scriptstr,uint64_t value,uint32_t *addrindp,uint32_t *scriptindp)
{
    struct coin777 *coin = state; uint32_t *ptr,addrind,scriptind = 0; int32_t tmp,len,scriptlen; uint8_t script[4096];
    struct Qaddr *addritem = 0; struct Qscript *scriptitem = 0; struct unspent_info *U; struct coin777_addrinfo *addrinfo;
    if ( (U= coin777_itemptr(coin,&coin->unspents,unspentind)) == 0 )
    {
        printf("coin777_addvout overflow? U.%p txidind.%u vs max.%u\n",U,unspentind,coin->unspents.maxitems);
        return(-1);
    }
    printf("T%u vo%-3d U%u %.8f %s %s\n",txidind,vout,unspentind,dstr(value),coinaddr,script);
    scriptlen = (int32_t)strlen(scriptstr) >> 1, decode_hex(script,scriptlen,scriptstr);
    len = (int32_t)strlen(coinaddr) + 1;
    if ( (addrind= coin777_findind(coin,&coin->addrs,(uint8_t *)coinaddr,len)) == 0 )
    {
        tmp = sizeof(addrind);
        if ( (ptr= db777_get(&addrind,&tmp,coin->DBs.transactions,coin->addrs.DB,coinaddr,len)) == 0 || addrind == 0 || tmp != sizeof(*ptr) )
        {
            addrind = ++(*addrindp);
            addrinfo = coin777_createaddr(coin,addrind,coinaddr,len,script,scriptlen);
            addritem = calloc(1,sizeof(*addritem) + len + 1), addritem->addrind = addrind, strcpy(addritem->coinaddr,coinaddr);
        } else addrinfo = coin777_itemptr(coin,&coin->addrinfos,addrind);
        coin777_addind(coin,&coin->addrs,addrinfo->coinaddr,len,addrind,&addritem->DL);
    }
    else if ( coin777_script0(coin,addrind,script,scriptlen) != 0 )
    {
        if ( (scriptind= coin777_findind(coin,&coin->scripts,script,scriptlen)) == 0 )
        {
            tmp = sizeof(scriptind);
            if ( (ptr= db777_get(&scriptind,&tmp,coin->DBs.transactions,coin->scripts.DB,script,scriptlen)) == 0 || scriptind == 0 || tmp != sizeof(*ptr) )
            {
                scriptind = ++(*scriptindp);
                scriptitem = calloc(1,sizeof(*scriptitem) + scriptlen), scriptitem->scriptind = scriptind, scriptitem->scriptlen = scriptlen, memcpy(scriptitem->script,script,scriptlen);
            }
            coin777_addind(coin,&coin->scripts,script,scriptlen,scriptind,&scriptitem->DL);
         }
    }
    coin777_addunspent(coin,&U[unspentind],addrind,scriptind,value,unspentind);
    return(0);
}

uint64_t coin777_addvin(void *state,uint32_t txidind,uint16_t vin,uint32_t totalspends,char *spent_txidstr,uint16_t spent_vout)
{
    struct coin777 *coin = state; bits256 txid; int32_t tmp; uint32_t *ptr,spent_txidind,*txoffsets,unspentind = 0; struct unspent_info *U = 0;
    printf("T%u vi%-3d S%u %s vout.%d\n",txidind,vin,totalspends,spent_txidstr,spent_vout);
    decode_hex(txid.bytes,sizeof(txid),spent_txidstr);
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
    if ( (txoffsets= coin777_itemptr(coin,&coin->txoffsets,spent_txidind)) != 0 )
    {
        unspentind = txoffsets[0] + spent_vout;
        if ( (U= coin777_itemptr(coin,&coin->unspents,unspentind)) != 0 )
        {
            if ( U->spending_txidind != 0 && U->spending_txidind != txidind )
                printf("unspentind.%u interloper txidind.%u overwrites.%u\n",unspentind,txidind,U->spending_txidind);
            U->spending_txidind = txidind, U->spending_vin = vin;
            coin777_addspend(coin,totalspends,U->addrind,unspentind,U->value,txidind,vin);
            return(U->value);
        } else printf("error getting unspents[%u]\n",unspentind);
    } else printf("error getting txoffsets for unspentind.%u spent_txidind.%u\n",unspentind,spent_txidind);
    return(0);
}

int32_t coin777_addfirstoffsets(uint32_t *txoffsets,uint32_t firstvout,uint32_t firstvin)
{
    int32_t err = 0;
    if ( txoffsets[0] != 0 && txoffsets[0] != firstvout )
        err = -2, printf("nonz firstvout.%u overwritten by %u\n",txoffsets[0],firstvout);
    txoffsets[0] = firstvout;
    if ( txoffsets[1] != 0 && txoffsets[1] != firstvin )
        err = -3, printf("nonz firstvin.%u overwritten by %u\n",txoffsets[1],firstvin);
    txoffsets[1] = firstvin;
    return(err);
}

int32_t coin777_addtx(void *state,uint32_t blocknum,uint32_t txidind,char *txidstr,uint32_t firstvout,uint16_t numvouts,uint64_t total,uint32_t firstvin,uint16_t numvins)
{
    struct coin777 *coin = state; bits256 txid,*txidbits; uint32_t *txoffsets = 0; struct Qtx *txitem; int32_t err = 0;
    if ( (txidbits= coin777_itemptr(coin,&coin->txidbits,txidind)) == 0 || (txoffsets= coin777_itemptr(coin,&coin->txoffsets,txidind)) == 0 )
    {
        printf("coin777_addtx offsets overflow? %p %p txidind.%u vs max.%u\n",txidbits,txoffsets,txidind,coin->txids.maxitems);
        return(-1);
    }
    printf("T%u U%u + %d, S%u + %d\n",txidind,firstvout,numvouts,firstvin,numvins);
    decode_hex(txid.bytes,sizeof(txid),txidstr);
    *txidbits = txid;
    err = coin777_addfirstoffsets(txoffsets,firstvout,firstvin), txoffsets += 2;
    err = coin777_addfirstoffsets(txoffsets,firstvout + numvouts,firstvin + numvins);
    txitem = calloc(1,sizeof(*txitem)), txitem->txid = txid, txitem->txidind = txidind;
    coin777_addind(coin,&coin->txids,txidbits,sizeof(*txidbits),txidind,&txitem->DL);
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
        retval = sp_set((transactions != 0 ? transactions : db),obj);
    }
    return(retval);
}

int32_t coin777_processQs(struct coin777 *coin)
{
    struct Qtx *tx; struct Qaddr *addr; struct Qscript *script; int32_t n = 0;
    while ( (tx= queue_dequeue(&coin->txids.writeQ,0)) != 0 )
    {
        printf("permanently store %llx -> txidind.%u\n",(long long)tx->txid.txid,tx->txidind);
        coin777_addDB(coin,coin->DBs.transactions,coin->txids.DB,tx->txid.bytes,sizeof(tx->txid),&tx->txidind,sizeof(tx->txidind));
        free(tx);
        n++;
    }
    while ( (addr= queue_dequeue(&coin->addrs.writeQ,0)) != 0 )
    {
        printf("permanently store (%s) -> addrind.%u\n",addr->coinaddr,addr->addrind);
        coin777_addDB(coin,coin->DBs.transactions,coin->addrs.DB,addr->coinaddr,(int32_t)strlen(addr->coinaddr)+1,&addr->addrind,sizeof(addr->addrind));
        free(addr);
        n++;
    }
    while ( (script= queue_dequeue(&coin->scripts.writeQ,0)) != 0 )
    {
        printf("permanently store (%llx) -> scriptind.%u\n",*(long long *)script->script,script->scriptind);
        coin777_addDB(coin,coin->DBs.transactions,coin->scripts.DB,script->script,script->scriptlen,&script->scriptind,sizeof(script->scriptind));
        free(script);
        n++;
    }
    return(n);
}

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

int32_t coin777_parse(void *state,struct coin777 *coin,uint32_t blocknum)
{
    uint32_t timestamp,txidind,numrawvouts,numrawvins,addrind,scriptind;
    if ( coin777_getinds(state,blocknum,&timestamp,&txidind,&numrawvouts,&numrawvins,&addrind,&scriptind) == 0 )
        return(parse_block(state,&txidind,&numrawvouts,&numrawvins,&addrind,&scriptind,coin->name,coin->serverport,coin->userpass,blocknum,coin777_addblock,coin777_addvin,coin777_addvout,coin777_addtx));
    else
    {
        printf("coin777 error getting inds for blocknum%u\n",blocknum);
        return(0);
    }
}

uint64_t coin777_permsize(void *state)
{
    int32_t i; struct coin777 *coin = state; uint64_t totalsize = 0;
    for (i=0; i<coin->DBs.numdbs; i++)
        totalsize += coin->latest.txidind * (2 * (sizeof(uint32_t) + sizeof(bits256)) + coin->latest.addrind * (36 + sizeof(struct coin777_addrinfo)) + coin->latest.unspentind * sizeof(struct unspent_info) + coin->latestblocknum * sizeof(struct coin_offsets));
    return(totalsize);
}
#endif
#endif
