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
struct rawvout { char coinaddr[128],script[1024]; uint64_t value; };
struct rawtx { uint16_t firstvin,numvins,firstvout,numvouts; char txidstr[128]; };

struct rawblock
{
    uint32_t blocknum;//,allocsize;format,
    uint16_t numtx,numrawvins,numrawvouts;
    uint64_t minted;
    struct rawtx txspace[MAX_BLOCKTX];
    struct rawvin vinspace[MAX_BLOCKTX];
    struct rawvout voutspace[MAX_BLOCKTX];
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

struct address_entry { uint32_t rawind:31,spent:1,blocknum,txind:15,vinflag:1,v:14,isinternal:1; };

struct sha256_state
{
    uint64_t length;
    uint32_t state[8],curlen;
    uint8_t buf[64];
};

struct ramchain_hashtable
{
    struct db777 *DB;
    char name[32];
    unsigned char hash[256 >> 3];
    uint32_t ind,maxind,type,minblocknum;
    struct sha256_state state;
};

struct ledger_addrinfo { int32_t count,allocated; int64_t balance; uint8_t addrlen,space[]; };
struct ledger_info
{
    char coinstr[16];
    struct sha256_state txoffsets_state,spentbits_state,addrinfos_state;
    unsigned char txoffsets_hash[256 >> 3],spentbits_hash[256 >> 3],addrinfos_hash[256 >> 3];
    struct ramchain_hashtable ledgers,addrs,txids,scripts,blocks,unspentmap;
    uint64_t voutsum,spendsum,addrsum;
    uint32_t needbackup,numtxoffsets,numaddrinfos,numspentbits,blocknum,blockpending,numptrs,totalvouts,totalspends,addrind,txidind,scriptind;
    uint32_t *txoffsets; uint8_t *spentbits; struct ledger_addrinfo **addrinfos;
};

struct ramchain
{
    char name[16];
    double lastgetinfo,startmilli;
    struct ramchain_hashtable *DBs[10];
    uint64_t totalsize;
    uint32_t startblocknum,RTblocknum,confirmednum,numDBs,numupdates,readyflag;
    //uint8_t *huffbits,*huffbits2;
    struct rawblock EMIT,DECODE;
    struct ledger_info L;
};

struct coin777
{
    char name[16],serverport[64],userpass[128],*jsonstr;
    cJSON *argjson;
    struct ramchain ramchain;
    int32_t use_addmultisig,gatewayid,multisigchar;
};

char *bitcoind_RPC(char **retstrp,char *debugstr,char *url,char *userpass,char *command,char *params);
char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params);
struct coin777 *coin777_create(char *coinstr,char *serverport,char *userpass,cJSON *argjson);
int32_t coin777_close(char *coinstr);
struct coin777 *coin777_find(char *coinstr);
char *extract_userpass(char *userhome,char *coindir,char *confname);
void ramchain_update(struct coin777 *coin);
int32_t rawblock_load(struct rawblock *raw,char *coinstr,char *serverport,char *userpass,uint32_t blocknum);
void rawblock_patch(struct rawblock *raw);

void update_sha256(unsigned char hash[256 >> 3],struct sha256_state *state,unsigned char *src,int32_t len);

#endif
#else
#ifndef crypto777_coins777_c
#define crypto777_coins777_c

#ifndef crypto777_coins777_h
#define DEFINES_ONLY
#include "coins777.c"
#endif

#endif
#endif
