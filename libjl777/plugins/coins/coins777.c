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
    char blockhash[4096],merkleroot[4096];
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
    struct ledger_state ledger,revaddrs,addrs,revtxids,txids,scripts,revscripts,blocks,unspentmap,txoffsets,spentbits,addrinfos;
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
    struct rawblock EMIT,DECODE;
    struct ledger_info *activeledger,*session_ledgers[1 << CONNECTION_NUMBITS];
};
 
struct coin777
{
    char name[16],serverport[64],userpass[128],*jsonstr;
    cJSON *argjson;
    double lastgetinfo;
    struct ramchain ramchain;
    uint32_t packedstart,packedend,packedincr,RTblocknum,packedblocknum,maxpackedblocks;
    int32_t use_addmultisig,minconfirms;
    struct rawblock EMIT;
    struct packedblock **packed;
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
struct packedblock *coin777_packrawblock(struct rawblock *raw);

#endif
#else
#ifndef crypto777_coins777_c
#define crypto777_coins777_c

#ifndef crypto777_coins777_h
#define DEFINES_ONLY
#include "coins777.c"
#endif

uint32_t coin777_packedoffset(struct alloc_space *mem,char *str,int32_t convflag)
{
    uint32_t offset,len; uint8_t _hex[8192],*hex = _hex;
    offset = (uint32_t)mem->used;
    len = (uint32_t)strlen(str) + 1;
    if ( convflag != 0 )
    {
        len >>= 1;
        if ( len >= sizeof(hex) )
        {
            printf("coin777_packedoffset: extreme len.%d for (%s)\n",len,str);
            hex = malloc(len);
        }
        decode_hex(hex,len,str);
        memcpy((void *)((long)mem->ptr + offset),hex,len);
        if ( hex != _hex )
            free(hex);
    } else memcpy((void *)((long)mem->ptr + offset),str,len);
    mem->used += len;
    return(offset);
}

void coin777_packtx(struct alloc_space *mem,struct packedtx *ptx,struct rawtx *tx)
{
    ptx->firstvin = tx->firstvin, ptx->numvins = tx->numvins, ptx->firstvout = tx->firstvout, ptx->numvouts = tx->numvouts;
    ptx->txidstroffset = coin777_packedoffset(mem,tx->txidstr,1);
}

void coin777_packvout(struct alloc_space *mem,struct packedvout *pvo,struct rawvout *vo)
{
    pvo->value = vo->value;
    pvo->coinaddroffset = coin777_packedoffset(mem,vo->coinaddr,0);
    pvo->scriptoffset = coin777_packedoffset(mem,vo->script,1);
}

void coin777_packvin(struct alloc_space *mem,struct packedvin *pvi,struct rawvin *vi)
{
    pvi->vout = vi->vout;
    pvi->txidstroffset = coin777_packedoffset(mem,vi->txidstr,1);
}

struct packedblock *coin777_packrawblock(struct rawblock *raw)
{
    static long totalsizes,totalpacked;
    struct rawtx *tx; struct rawvin *vi; struct rawvout *vo; struct alloc_space MEM,*mem = &MEM;
    struct packedtx *ptx; struct packedvin *pvi; struct packedvout *pvo; struct packedblock *packed = 0;
    uint32_t i,txind,n,crc;
    tx = raw->txspace, vi = raw->vinspace, vo = raw->voutspace;
    mem = init_alloc_space(0,0,sizeof(struct rawblock) + raw->numtx*sizeof(struct rawtx) + raw->numrawvouts*sizeof(struct rawvout) + raw->numrawvins*sizeof(struct rawvin),0);
    packed = memalloc(mem,sizeof(*packed),1);
    packed->numtx = raw->numtx, packed->numrawvins = raw->numrawvins, packed->numrawvouts = raw->numrawvouts;
    packed->blocknum = raw->blocknum, packed->timestamp = raw->timestamp, packed->minted = raw->minted;
    packed->blockhash_offset = coin777_packedoffset(mem,raw->blockhash,1);
    packed->merkleroot_offset = coin777_packedoffset(mem,raw->merkleroot,1);
    packed->txspace_offsets = (uint32_t)mem->used, ptx = memalloc(mem,raw->numtx*sizeof(struct packedtx),0);
    packed->vinspace_offsets = (uint32_t)mem->used, pvo = memalloc(mem,raw->numrawvouts*sizeof(struct packedvout),0);
    packed->voutspace_offsets = (uint32_t)mem->used, pvi = memalloc(mem,raw->numrawvins*sizeof(struct packedvin),0);
    if ( raw->numtx > 0 )
    {
        for (txind=0; txind<raw->numtx; txind++,tx++,ptx++)
        {
            coin777_packtx(mem,ptx,tx);
            if ( (n= tx->numvouts) > 0 )
                for (i=0; i<n; i++,vo++,pvo++)
                    coin777_packvout(mem,pvo,vo);
            if ( (n= tx->numvins) > 0 )
                for (i=0; i<n; i++,vi++,pvi++)
                    coin777_packvin(mem,pvi,vi);
        }
    }
    packed->allocsize = (uint32_t)mem->used;
    crc = _crc32(0,(uint8_t *)&packed[sizeof(packed->crc16)],(int32_t)(packed->allocsize - sizeof(packed->crc16)));
    packed->crc16 = (((crc >> 16) & 0xffff) ^ (uint16_t)crc);
    totalsizes += mem->size, totalpacked += mem->used;
    printf("block.%u packed sizes: block.%ld tx.%ld vin.%ld vout.%ld | mem->size %ld -> %d %s vs %s [%.3f]\n",raw->blocknum,sizeof(struct packedblock),sizeof(struct packedtx),sizeof(struct packedvout),sizeof(struct packedvin),mem->size,packed->allocsize,_mbstr(totalsizes),_mbstr2(totalpacked),(double)totalsizes / totalpacked);
    packed = malloc(mem->used), memcpy(packed,mem->ptr,mem->used), free(mem);
    return(packed);
}

#endif
#endif
