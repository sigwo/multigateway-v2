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

struct ledgerinds
{
    struct sha256_state shastates[6];
    unsigned char hashes[6][256 >> 3];
    uint64_t voutsum,spendsum,addrsum;
    uint32_t numtxoffsets,numaddrinfos,numspentbits,blocknum,totalvouts,totalspends,txidind,addrind,scriptind;
};

struct ledger_addrinfo { int32_t count,allocated; int64_t balance; uint32_t unspentinds[]; };
struct ledger_info
{
    struct sha256_state txoffsets_state,spentbits_state,addrinfos_state;
    unsigned char txoffsets_hash[256 >> 3],spentbits_hash[256 >> 3],addrinfos_hash[256 >> 3];
    char coinstr[16]; long unsaved; struct ledgerinds L;
    struct ramchain_hashtable ledgers,addrs,txids,scripts,blocks,unspentmap,*DBs[10];
    uint32_t blockpending,numptrs,numDBs;
    uint32_t *txoffsets; uint8_t *spentbits; struct ledger_addrinfo **addrinfos;
};

struct ramchain
{
    char name[16];
    double lastgetinfo,startmilli;
    struct ledger_info ledger;
    //struct unspent_entry **addr_unspents;
    uint64_t totalsize;
    uint32_t startblocknum,RTblocknum,blocknum,confirmednum,huffallocsize,numupdates,readyflag;
    //struct ramchain_hashtable blocks,addrs,txids,scripts,unspents;
    uint8_t *huffbits,*huffbits2;
    struct rawblock EMIT,DECODE;
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

struct ledger_txinfo { uint32_t firstvout,firstvin; uint16_t numvouts,numvins; uint8_t txidlen,txid[255]; };
struct ledger_spendinfo { uint32_t unspentind,txidind; uint16_t vout; };
struct ledger_voutdata { uint64_t value; uint32_t addrind,scriptind; int32_t addrlen,scriptlen,newscript,newaddr; char coinaddr[256]; uint8_t script[256]; };

uint32_t *ledger_packtx(struct ledger_txinfo *tx)
{
    uint32_t *ptr; int32_t allocsize;
    allocsize = sizeof(tx->firstvout) + sizeof(tx->firstvin) + sizeof(tx->numvouts) + sizeof(tx->numvins) + tx->txidlen + 1;
    //printf("ledger_packtx %d\n",allocsize);
    ptr = calloc(1,allocsize + sizeof(*ptr));
    //printf("ledger_packtx %d %p\n",allocsize,ptr);
    ptr[0] = allocsize;
    memcpy(&ptr[1],tx,allocsize);
    return(ptr);
}

uint32_t *ledger_packspend(struct ledger_spendinfo *spend)
{
    uint32_t *ptr;
    ptr = calloc(1,sizeof(spend->unspentind) + sizeof(*ptr));
    //printf("ledger_packsend %d %p\n",spend->unspentind,ptr);
    ptr[0] = sizeof(spend->unspentind);
    ptr[1] = spend->unspentind;
    return(ptr);
}

void ledger_packvoutstr(void *data,struct alloc_space *mem,uint32_t rawind,int32_t newitem,uint8_t *str,uint8_t len)
{
    if ( newitem != 0 )
    {
        rawind |= (1 << 31);
        data = memalloc(mem,sizeof(rawind)), memcpy(data,&rawind,sizeof(rawind));
        data = memalloc(mem,sizeof(len)), memcpy(data,&len,sizeof(len));
        data = memalloc(mem,len), memcpy(data,str,len);
    }
    else data = memalloc(mem,sizeof(rawind)), memcpy(data,&rawind,sizeof(rawind));
}

uint32_t *ledger_packvout(struct ledger_voutdata *vout)
{
    uint32_t *ptr; void *data; struct alloc_space mem;
    ptr = calloc(1,sizeof(*vout) + sizeof(*ptr));
    //printf("packvout %ld %p\n",sizeof(*vout) + sizeof(*ptr),ptr);
    memset(&mem,0,sizeof(mem)); mem.ptr = &ptr[1]; mem.size = sizeof(*vout);
    data = memalloc(&mem,sizeof(vout->value)), memcpy(data,&vout->value,sizeof(vout->value));
    ledger_packvoutstr(data,&mem,vout->addrind,vout->newaddr,(uint8_t *)vout->coinaddr,vout->addrlen);
    ledger_packvoutstr(data,&mem,vout->scriptind,vout->newscript,vout->script,vout->scriptlen);
    //printf("packed vout used.%ld size.%ld\n",mem.used,mem.size);
    ptr[0] = (uint32_t)mem.used;
    return(ptr);
}

int32_t ledger_saveaddrinfo(FILE *fp,struct ledger_addrinfo *addrinfo)
{
    int32_t allocsize,zero = 0;
    if ( addrinfo == 0 )
        return(fwrite(&zero,1,sizeof(zero),fp) == sizeof(zero));
    else
    {
        allocsize = (sizeof(*addrinfo) + addrinfo->count * sizeof(*addrinfo->unspentinds));
        return(fwrite(addrinfo,1,allocsize,fp) == allocsize);
    }
}

int32_t ledger_save(struct ledger_info *ledger,int32_t blocknum)
{
    FILE *fp; long fpos; void *block; int32_t i,err = 0; uint64_t allocsize = 0;
    char ledgername[512];
    sprintf(ledgername,"/tmp/%s.%u",ledger->coinstr,blocknum);
    if ( (fp= fopen(ledgername,"wb")) != 0 )
    {
        if ( fwrite(&ledger->L,1,sizeof(ledger->L),fp) != sizeof(ledger->L) )
            err++, printf("error saving (%s) L\n",ledgername);
        else if ( fwrite(&ledger->txoffsets,ledger->L.numtxoffsets,2*sizeof(*ledger->txoffsets),fp) != (2 * sizeof(*ledger->txoffsets)) )
            err++, printf("error saving (%s) numtxoffsets.%d\n",ledgername,ledger->L.numtxoffsets);
        else if ( fwrite(&ledger->spentbits,1,(ledger->L.numspentbits>>3)+1,fp) != ((ledger->L.numspentbits >> 3) + 1) )
            err++, printf("error saving (%s) spentbits.%d\n",ledgername,ledger->L.numspentbits);
        else
        {
            for (i=0; i<ledger->L.numaddrinfos; i++)
                if ( ledger_saveaddrinfo(fp,ledger->addrinfos[i]) <= 0 )
                {
                    err++, printf("error saving addrinfo.%d (%s)\n",i,ledgername);
                    break;
                }
        }
        fpos = ftell(fp);
        rewind(fp);
        fclose(fp);
        if ( (block= loadfile(&allocsize,ledgername)) != 0 && (allocsize == fpos || allocsize == fpos+1) )
        {
            if ( db777_add(0,ledger->ledgers.DB,&blocknum,sizeof(blocknum),block,(int32_t)fpos) != 0 )
                printf("error saving (%s) %ld\n",ledgername,fpos);
            else printf("saved (%s) %ld %s\n",ledgername,fpos,_mbstr(fpos));
            free(block);
            return(0);
        } else printf("error loading (%s) allocsize.%llu vs %ld\n",ledgername,(long long)allocsize,fpos);
    }
    return(-1);
}

int32_t ledger_setinds(struct ledger_info *ledger,struct ledgerinds *lp,uint32_t blocknum)
{
    if ( blocknum == 1 )
    {
        memset(lp,0,sizeof(*lp));
        lp->txidind = lp->addrind = lp->scriptind = 1;
    }
    else if ( blocknum == ledger->L.blocknum )
        *lp = ledger->L;
    else
    {
        printf("need to code reprocessing from closest ledger\n");
        // load closest checkpoint, reprocess tx to blocknum
    }
    return(0);
}

/*uint16_t block_crc16(struct block_output *block)
{
    uint32_t crc32 = _crc32(0,(void *)((long)&block->crc16 + sizeof(block->crc16)),block->allocsize - sizeof(block->crc16));
    return((crc32 >> 16) ^ (crc32 & 0xffff));
}*/

uint32_t ledger_rawind(struct ramchain_hashtable *hash,void *key,int32_t keylen)
{
    int32_t size; uint32_t *ptr,rawind = 0;
    if ( (ptr= db777_findM(&size,hash->DB,key,keylen)) != 0 )
    {
        if ( size == sizeof(uint32_t) )
        {
            rawind = *ptr;
            if ( (rawind - 1) == hash->ind )
                hash->ind = rawind;
            if ( hash->ind > hash->maxind )
                hash->maxind = hash->ind;
            //printf("found keylen.%d rawind.%d (%d %d)\n",keylen,rawind,hash->ind,hash->maxind);
        }
        else printf("error unexpected size.%d for (%s) keylen.%d\n",size,hash->name,keylen);
        free(ptr);
        return(rawind);
    }
    rawind = ++hash->ind;
    //printf("add rawind.%d keylen.%d\n",rawind,keylen);
    if ( db777_add(1,hash->DB,key,keylen,&rawind,sizeof(rawind)) != 0 )
        printf("error adding to %s DB for rawind.%d keylen.%d\n",hash->name,rawind,keylen);
    else
    {
        update_sha256(hash->hash,&hash->state,key,keylen);
        return(rawind);
    }
    return(0);
}

uint32_t ledger_hexind(struct ramchain_hashtable *hash,uint8_t *data,int32_t *hexlenp,char *hexstr)
{
    int32_t hexlen;
    hexlen = (int32_t)strlen(hexstr) >> 1;
    //printf("hexlen.%d (%s)\n",hexlen,hexstr);
    if ( hexlen < 255 )
    {
        decode_hex(data,hexlen,hexstr);
        return(ledger_rawind(hash,data,hexlen));
    }
    else
    {
        printf("hexlen overflow (%s) -> %d\n",hexstr,hexlen);
        return(0);
    }
}

void *ledger_unspent(struct ledger_info *ledger,uint32_t txidind,uint32_t unspentind,char *coinaddr,char *scriptstr,uint64_t value)
{
    int32_t n,width = 1024; struct ledger_addrinfo *addrinfo; struct ledger_voutdata vout;
    memset(&vout,0,sizeof(vout));
    vout.value = value;
    //printf("unspent.%d (%s) (%s) %.8f\n",unspentind,coinaddr,scriptstr,dstr(value));
    ledger->L.voutsum += value;
    //printf("%.8f ",dstr(value));
    if ( (vout.scriptind= ledger_hexind(&ledger->scripts,vout.script,&vout.scriptlen,scriptstr)) == 0 )
    {
        printf("ledger_unspent: error getting scriptind.(%s)\n",scriptstr);
        return(0);
    }
    vout.newscript = (vout.scriptind == ledger->scripts.ind);
    vout.addrlen = (int32_t)strlen(coinaddr);
    if ( (vout.addrind= ledger_rawind(&ledger->addrs,coinaddr,vout.addrlen)) != 0 )
    {
        //printf("vout.addrind.%d vs ledger->addrs.ind %d | %s\n",vout.addrind,ledger->addrs.ind,vout.newscript!=0?"EMIT SCRIPT":"");
        ledger->unspentmap.ind = ledger->unspentmap.maxind = unspentind;
        if ( db777_add(0,ledger->unspentmap.DB,&unspentind,sizeof(unspentind),&vout,sizeof(vout.value)+sizeof(vout.addrind)) != 0 )
            printf("error saving unspentmap (%s) %u -> %u\n",ledger->coinstr,unspentind,vout.addrind);
        //else printf("saved unspentmap (%s) %u -> addrind.%u %.8f | (%s)\n",ledger->coinstr,unspentind,vout.addrind,dstr(value),coinaddr);
        if ( vout.addrind == ledger->addrs.ind )
            vout.newaddr = 1, strcpy(vout.coinaddr,coinaddr);
        //printf("script (%d %d) addr (%d %d)\n",vout.scriptind,ledger->scripts.ind,vout.addrind,ledger->addrs.ind);
        if ( vout.addrind >= ledger->L.numaddrinfos )
        {
            n = (ledger->L.numaddrinfos + width);
            if ( ledger->addrinfos != 0 )
            {
                ledger->addrinfos = realloc(ledger->addrinfos,sizeof(*ledger->addrinfos) * n);
                memset(&ledger->addrinfos[ledger->L.numaddrinfos],0,sizeof(*ledger->addrinfos) * width);
            }
            else ledger->addrinfos = calloc(width,sizeof(*ledger->addrinfos));
            ledger->L.numaddrinfos += width;
        }
        if ( (addrinfo= ledger->addrinfos[vout.addrind]) == 0 )
        {
            ledger->addrinfos[vout.addrind] = addrinfo = calloc(1,sizeof(*addrinfo) + sizeof(*addrinfo->unspentinds));
            addrinfo->allocated = addrinfo->count = 1;
            addrinfo->unspentinds[0] = unspentind;
            addrinfo->balance += value;
            update_sha256(ledger->addrinfos_hash,&ledger->addrinfos_state,(uint8_t *)&vout,sizeof(vout));
            return(ledger_packvout(&vout));
        }
        if ( (n= addrinfo->count) >= addrinfo->allocated )
        {
            width = ((n + 1) << 1);
            if ( width > 256 )
                width = 256;
            n = (addrinfo->count + width);
            //printf("realloc width.%d n.%d addrinfo unspentinds\n",width,n);
            ledger->addrinfos[vout.addrind] = addrinfo = realloc(addrinfo,sizeof(*addrinfo) + (sizeof(*addrinfo->unspentinds) * n));
            memset(&addrinfo->unspentinds[addrinfo->count],0,sizeof(*addrinfo->unspentinds) * width);
            addrinfo->allocated = (addrinfo->count + width);
            //printf("new max.%d count.%d\n",unspents->max,unspents->count);
        }
        addrinfo->balance += value;
        addrinfo->unspentinds[addrinfo->count++] = unspentind;
        update_sha256(ledger->addrinfos_hash,&ledger->addrinfos_state,(uint8_t *)&vout,sizeof(vout));
        return(ledger_packvout(&vout));
    } else printf("ledger_unspent: cant find addrind.(%s)\n",coinaddr);
    return(0);
}

void *ledger_spend(struct ledger_info *ledger,uint32_t spend_txidind,uint32_t totalspends,char *spent_txidstr,uint16_t vout)
{
    int32_t i,n,size,txidlen,addrind; uint64_t value; uint32_t txidind,*ptr; uint8_t txid[256];
    struct ledger_spendinfo spend; struct ledger_addrinfo *addrinfo;
    //printf("spend_txidind.%d totalspends.%d (%s).v%d\n",spend_txidind,totalspends,spent_txidstr,vout);
    if ( (txidind= ledger_hexind(&ledger->txids,txid,&txidlen,spent_txidstr)) != 0 )
    {
        memset(&spend,0,sizeof(spend));
        spend.txidind = txidind, spend.vout = vout;
        spend.unspentind = ledger->txoffsets[txidind << 1] + vout;
        SETBIT(ledger->spentbits,spend.unspentind);
        if ( (ptr= db777_findM(&size,ledger->unspentmap.DB,&spend.unspentind,sizeof(spend.unspentind))) == 0 || size != 12 )
        {
            if ( ptr != 0 )
                free(ptr);
            for (i=txidind-100; i<=txidind; i++)
                if ( i >= 0 )
                    printf("%d.(%d %d) ",i,ledger->txoffsets[i*2],ledger->txoffsets[i*2+1]);
            printf("error loading unspentmap (%s) unspentind.%u | txidind.%d vout.%d\n",ledger->coinstr,spend.unspentind,txidind,vout);
            return(0);
        }
        value = *(uint64_t *)ptr, addrind = ptr[2], free(ptr);
        ledger->L.spendsum += value;
        //printf("-%.8f ",dstr(value));
        update_sha256(ledger->spentbits_hash,&ledger->spentbits_state,(uint8_t *)&spend.unspentind,sizeof(spend.unspentind));
        if ( (addrinfo= ledger->addrinfos[addrind]) == 0 )
        {
            printf("null addrinfo for addrind.%d max.%d, unspentind.%d %.8f\n",addrind,ledger->addrs.ind,spend.unspentind,dstr(value));
            return(0);
        }
       // printf("addrinfo.%p for addrind.%d max.%d, unspentind.%d %.8f\n",addrinfo,addrind,ledger->addrs.ind,spend.unspentind,dstr(value));
        if ( (n= addrinfo->count) > 0 )
        {
            for (i=0; i<n; i++)
            {
                if ( addrinfo->unspentinds[i] == spend.unspentind )
                {
                    addrinfo->balance -= value;
                    addrinfo->unspentinds[i] = addrinfo->unspentinds[--addrinfo->count];
                    memset(&addrinfo->unspentinds[addrinfo->count],0,sizeof(addrinfo->unspentinds[addrinfo->count]));
                    ///printf("found matched unspentind.%u in slot.[%d] max.%d count.%d -> %.8f\n",spend.unspentind,i,addrinfo->allocated,addrinfo->count,dstr(addrinfo->balance));
                    break;
                }
            }
            if ( i == n )
            {
                printf("cant find unspentind.%u for (%s).v%d\n",spend.unspentind,spent_txidstr,vout);
                return(0);
            }
        }
        return(ledger_packspend(&spend));
    } else printf("ledger_spend: cant find txidind for (%s).v%d\n",spent_txidstr,vout);
    return(0);
}

void *ledger_tx(struct ledger_info *ledger,uint32_t txidind,char *txidstr,uint32_t totalvouts,uint16_t numvouts,uint32_t totalspends,uint16_t numvins)
{
    uint32_t checkind,*offsets; uint8_t txid[256]; struct ledger_txinfo tx; int32_t i,txidlen,n,width = 4096;
    //printf("ledger_tx txidind.%d %s vouts.%d vins.%d | ledger->numtxoffsets %d\n",txidind,txidstr,totalvouts,totalspends,ledger->L.numtxoffsets);
    if ( (checkind= ledger_hexind(&ledger->txids,txid,&txidlen,txidstr)) == txidind )
    {
        memset(&tx,0,sizeof(tx));
        tx.firstvout = totalvouts, tx.firstvin = totalspends;
        tx.numvouts = numvouts, tx.numvins = numvins;
        tx.txidlen = txidlen;
        memcpy(tx.txid,txid,txidlen);
        if ( (txidind + 1) >= ledger->L.numtxoffsets )
        {
            n = ledger->L.numtxoffsets + width;
            //printf("realloc ledger->numtxoffsets n.%d\n",n);
            ledger->txoffsets = realloc(ledger->txoffsets,sizeof(uint32_t) * 2 * n);
            memset(&ledger->txoffsets[ledger->L.numtxoffsets << 1],0,width * 2 * sizeof(uint32_t));
            ledger->L.numtxoffsets += width;
        }
        if ( (totalvouts + numvouts) >= ledger->L.numspentbits )
        {
            n = ledger->L.numspentbits + width;
            ledger->spentbits = realloc(ledger->spentbits,(n >> 3) + 1);
            for (i=0; i<width; i++)
                CLEARBIT(ledger->spentbits,ledger->L.numspentbits + i);
            ledger->L.numspentbits += width;
        }
        offsets = &ledger->txoffsets[txidind << 1];
        offsets[0] = totalvouts, offsets[1] = totalspends;
        offsets[2] = totalvouts + numvouts, offsets[3] = totalspends + numvins;
        update_sha256(ledger->txoffsets_hash,&ledger->txoffsets_state,(uint8_t *)&offsets[2],sizeof(offsets[0]) * 2);
        //printf("offsets txind.%d (%d %d), next (%d %d)\n",txidind,offsets[0],offsets[1],offsets[2],offsets[3]);
        return(ledger_packtx(&tx));
    } else printf("ledger_tx: mismatched txidind, expected %u got %u\n",txidind,checkind), getchar();
    return(0);
}

uint32_t **ledger_startblock(void *_ledger,uint32_t blocknum,int32_t numevents)
{
    struct ledger_info *ledger = _ledger;
    uint32_t **ptrs = calloc(numevents,sizeof(*ptrs));
    if ( ledger->blockpending != 0 )
    {
        printf("ledger_startblock: cant startblock when %s %u is pending\n",ledger->coinstr,ledger->L.blocknum);
        return(0);
    }
    ledger->blockpending = 1, ledger->L.blocknum = blocknum, ledger->numptrs = numevents;
    // start DB transactions
    return(ptrs);
}

int32_t ledger_commitblock(struct ledger_info *ledger,uint32_t **ptrs,int32_t numptrs,uint32_t blocknum,struct ledgerinds *lp,int32_t sync)
{
    int32_t i,len,n,errs,allocsize = 0;
    uint8_t *blocks;
    if ( ledger->blockpending == 0 || ledger->L.blocknum != blocknum || ledger->numptrs != numptrs )
    {
        printf("ledger_commitblock: error mismatched parameter pending.%d (%d %d) (%d %d)\n",ledger->blockpending,ledger->L.blocknum,blocknum,ledger->numptrs,numptrs);
        return(-1);
    }
    for (i=0; i<numptrs; i++)
        if ( ptrs[i] != 0 )
            allocsize += ptrs[i][0];//, printf("%d ",ptrs[i][0]);
    if ( allocsize > 0 )
    {
        blocks = malloc(allocsize);
        for (i=n=errs=0; i<numptrs; i++)
        {
            if ( ptrs[i] != 0 )
            {
                len = ptrs[i][0];
                memcpy(&blocks[n],&ptrs[i][1],len);
                n += len;
                free(ptrs[i]);
            } else errs++;
        }
        free(ptrs);
        if ( errs != 0 || db777_add(0,ledger->blocks.DB,blocks,allocsize,&blocknum,sizeof(blocknum)) != 0 )
        {
            printf("errs.%d error saving blocks %s %u\n",errs,ledger->coinstr,blocknum);
            getchar();
            free(blocks);
            return(-1);
        }
        free(blocks);
    }
    lp->blocknum = blocknum;
    lp->txidind = ledger->txids.ind, lp->scriptind = ledger->scripts.ind, lp->addrind = ledger->addrs.ind;
    lp->shastates[0] = ledger->txids.state, lp->shastates[1] = ledger->scripts.state, lp->shastates[2] = ledger->addrs.state;
    lp->shastates[3] = ledger->txoffsets_state, lp->shastates[4] = ledger->spentbits_state, lp->shastates[5] = ledger->addrinfos_state;
    memcpy(lp->hashes[0],ledger->txids.hash,sizeof(ledger->txids.hash));
    memcpy(lp->hashes[1],ledger->scripts.hash,sizeof(ledger->scripts.hash));
    memcpy(lp->hashes[2],ledger->addrs.hash,sizeof(ledger->addrs.hash));
    memcpy(lp->hashes[3],ledger->txoffsets_hash,sizeof(ledger->txoffsets_hash));
    memcpy(lp->hashes[4],ledger->spentbits_hash,sizeof(ledger->spentbits_hash));
    memcpy(lp->hashes[5],ledger->addrinfos_hash,sizeof(ledger->addrinfos_hash));
    ledger->L = *lp;
    // commit all events to DB's
    if ( sync != 0 && ledger_save(ledger,blocknum + 1) == 0 )
        ledger->unsaved = 0;
    ledger->numptrs = ledger->blockpending = 0;
    return(allocsize);
}

int32_t ramchain_ledgerupdate(struct ledger_info *ledger,struct coin777 *coin,struct rawblock *emit,uint32_t blocknum)
{
    struct rawtx *tx; struct rawvin *vi; struct rawvout *vo; uint32_t **ptrs; int32_t allocsize = 0;
    uint32_t i,numtx,txind,numspends,numvouts,n,m = 0;
    struct ledger_addrinfo *addrinfo;
    struct ledgerinds *lp = &ledger->L;
    //printf("ledgerupdate block.%u txidind.%u/%u addrind.%u/%u scriptind.%u/%u unspentind.%u/%u\n",blocknum,lp->txidind,ledger->txids.ind,lp->addrind,ledger->addrs.ind,lp->scriptind,ledger->scripts.ind,lp->totalvouts,ledger->unspentmap.ind);
    if ( blocknum == 1 )
    {
        uint8_t hash[256 >> 3];
        update_sha256(hash,&ledger->ledgers.state,0,0);
        update_sha256(hash,&ledger->unspentmap.state,0,0);
        update_sha256(hash,&ledger->blocks.state,0,0);
        update_sha256(hash,&ledger->addrs.state,0,0);
        update_sha256(hash,&ledger->txids.state,0,0);
        update_sha256(hash,&ledger->scripts.state,0,0);
        lp->addrind = lp->scriptind = 1;
    }
    if ( rawblock_load(emit,coin->name,coin->serverport,coin->userpass,blocknum) > 0 )
    {
        tx = emit->txspace, numtx = emit->numtx, vi = emit->vinspace, vo = emit->voutspace;
        for (i=numspends=numvouts=0; i<numtx; i++)
            numspends += tx[i].numvins, numvouts += tx[i].numvouts;
        ptrs = ledger_startblock(ledger,blocknum,numtx + numspends + numvouts);
        if ( numtx > 0 )
        {
            //if ( ledger_setinds(ledger,&L,blocknum) == 0 )
            {
                for (txind=0; txind<numtx; txind++,tx++)
                {
                    lp->txidind++;
                    ptrs[m++] = ledger_tx(ledger,lp->txidind,tx->txidstr,lp->totalvouts+1,tx->numvouts,lp->totalspends+1,tx->numvins);
                    if ( (n= tx->numvouts) > 0 )
                        for (i=0; i<n; i++,vo++)
                            ptrs[m++] = ledger_unspent(ledger,lp->txidind,++lp->totalvouts,vo->coinaddr,vo->script,vo->value);
                    if ( (n= tx->numvins) > 0 )
                        for (i=0; i<n; i++,vi++)
                            ptrs[m++] = ledger_spend(ledger,lp->txidind,++lp->totalspends,vi->txidstr,vi->vout);
                }
            }
            //else printf("error ledger_setinds %s %u\n",coin->name,blocknum);
        }
        ledger->L.addrsum = 0;
        for (i=1; i<=ledger->addrs.ind; i++)
            if ( (addrinfo= ledger->addrinfos[i]) != 0 )
                ledger->L.addrsum += addrinfo->balance;
        if ( (allocsize= ledger_commitblock(ledger,ptrs,m,blocknum,lp,ledger->unsaved > 10000000)) < 0 )
        {
            printf("error updating %s block.%u\n",coin->name,blocknum);
            return(-1);
        }
        ledger->unsaved += allocsize;
    } else printf("error loading %s block.%u\n",coin->name,blocknum);
    //printf("ledgerupdateD block.%u txidind.%u/%u addrind.%u/%u scriptind.%u/%u unspentind.%u/%u\n",blocknum,lp->txidind,ledger->txids.ind,lp->addrind,ledger->addrs.ind,lp->scriptind,ledger->scripts.ind,lp->totalvouts,ledger->unspentmap.ind);
    return(allocsize);
}

/*int32_t ramchain_decode(struct ramchain *ram,struct alloc_space *mem,struct block_output *block,struct rawtx *tx,struct rawvin *vi,struct rawvout *vo,struct address_entry *bp)
{
    struct unspent_output *unspents; uint32_t *spendinds; uint16_t *offsets;
    uint32_t checksize; uint16_t voutoffset,spendoffset,n;
    offsets = (void *)((long)block + sizeof(struct block_output));
    spendinds = (void *)((long)offsets + sizeof(*offsets) * (block->numtx+1) * 2);
    unspents = (void *)((long)spendinds + sizeof(*spendinds) * block->totalspends);
    checksize = (uint32_t)((long)unspents + (sizeof(*unspents) * block->totalvouts) - (long)block);
    if ( bp->blocknum == block->blocknum && checksize == block->allocsize && block_crc16(block) == block->crc16 )
    {
        if ( block->numtx > 0 )
        {
            for (bp->txind=voutoffset=spendoffset=0; bp->txind<block->numtx; bp->txind++,tx++)
            {
                //printf("txind.%d ",bp->txind);
                if ( spendoffset != offsets[(bp->txind << 1) + 0] || voutoffset != offsets[(bp->txind << 1) + 1] )
                {
                    printf("offset mismatch %s block.%d txind.%d (%d %d %d %d)\n",ram->name,bp->blocknum,bp->txind,spendoffset,offsets[(bp->txind << 1) + 0],voutoffset,offsets[(bp->txind << 1) + 1]);
                }
                if ( (n= (offsets[((bp->txind+1) << 1) + 0] - offsets[(bp->txind << 1) + 0])) > 0 )
                {
                   // printf("numvins.%d ",n);
                    bp->vinflag = 1;
                    for (bp->v=0; bp->v<n; bp->v++,vi++)
                        unspent_decode_vi(ram,vi,spendinds[spendoffset++]);
                }
                if ( (n= (offsets[((bp->txind+1) << 1) + 1] - offsets[(bp->txind << 1) + 1])) > 0 )
                {
                    //printf("numvouts.%d ",n);
                    bp->vinflag = 0;
                    for (bp->v=0; bp->v<n; bp->v++,vo++)
                        unspent_decode_vo(ram,vo,unspents[voutoffset++]);
                }
                txid_decode_tx(tx,&ram->txids,block->first_txidind + bp->txind);
            }
        }
    } else printf("checksize error %d vs allocsize %d | crc16 %d vs %d\n",checksize,block->allocsize,block_crc16(block),block->crc16);
    return(block->numtx);
}*/

int32_t ramchain_processblock(struct coin777 *coin,uint32_t blocknum,uint32_t RTblocknum)
{
    struct ramchain *ram = &coin->ramchain;
    int32_t len; double estimate,elapsed;
    uint64_t supply,oldsupply = ram->ledger.L.voutsum - ram->ledger.L.spendsum;
    if ( (ram->RTblocknum % 1000) == 0 )
        ram->RTblocknum = _get_RTheight(&ram->lastgetinfo,coin->name,coin->serverport,coin->userpass,ram->RTblocknum);
    len = ramchain_ledgerupdate(&ram->ledger,coin,&ram->EMIT,blocknum);
    ram->totalsize += len;
    //len = ramchain_rawblock(ram,&ram->EMIT,blocknum,1), memset(ram->huffbits,0,ram->huffallocsize);
    //ramchain_rawblock(ram,&ram->DECODE,blocknum,0);
    estimate = estimate_completion(ram->startmilli,blocknum-ram->startblocknum,RTblocknum-blocknum)/60000;
    elapsed = (milliseconds()-ram->startmilli)/60000.;
    supply = ram->ledger.L.voutsum - ram->ledger.L.spendsum;
    printf("%-4s [lag %-5d] block.%-6u supply %.8f %.8f (%.8f) [%.8f] seconds %.2f %.2f %.2f | len.%-5d %s %.1f per block\n",coin->name,RTblocknum-blocknum,blocknum,dstr(supply),dstr(ram->ledger.L.addrsum),dstr(supply)-dstr(ram->ledger.L.addrsum),dstr(supply)-dstr(oldsupply),elapsed,estimate,elapsed+estimate,len,_mbstr(ram->totalsize),(double)ram->totalsize/blocknum);
    return(0);
    rawblock_patch(&ram->EMIT), rawblock_patch(&ram->DECODE);
    ram->DECODE.minted = ram->EMIT.minted = 0;
    if ( (len= memcmp(&ram->EMIT,&ram->DECODE,sizeof(ram->EMIT))) != 0 )
    {
        int i,n = 0;
        for (i=0; i<sizeof(ram->DECODE); i++)
            if ( ((char *)&ram->EMIT)[i] != ((char *)&ram->DECODE)[i] )
                printf("(%02x v %02x).%d ",((uint8_t *)&ram->EMIT)[i],((uint8_t *)&ram->DECODE)[i],i),n++;
        printf("COMPARE ERROR at %d | numdiffs.%d size.%ld\n",len,n,sizeof(ram->DECODE));
    }
    return(0);
}

void ramchain_syncDB(struct ramchain_hashtable *hash)
{
    //int32_t bval,cval;
    //bval = sp_set(hash->DB->ctl,"backup.run");
    //cval = sp_set(hash->DB->ctl,"scheduler.checkpoint");
    //printf("hash.(%c) bval.%d cval.%d\n",hash->type,bval,cval);
}

void ramchain_syncDBs(struct ramchain *ram)
{
    int32_t i;
    for (i=0; i<ram->ledger.numDBs; i++)
        ramchain_syncDB(ram->ledger.DBs[i]);
}

/*int32_t ramchain_setblocknums(struct ramchain *ram,uint32_t minblocknum,int32_t deleteflag)
{
    int32_t i,numpurged = 0;
    for (i=0; i<ram->ledger.numDBs; i++)
        numpurged += ramchain_setblocknum(ram->ledger.DBs[i],minblocknum,deleteflag);
    return(numpurged);
}*/

uint32_t init_hashDBs(struct ramchain *ram,char *coinstr,struct ramchain_hashtable *hash,char *name,char *compression)
{
    if ( hash->DB == 0 )
    {
        hash->DB = db777_create("ramchains",coinstr,name,compression);
        hash->type = name[0];
        strcpy(hash->name,name);
        printf("need to make ramchain_inithash\n");
        //hash->minblocknum = ramchain_inithash(hash);
        ram->ledger.DBs[ram->ledger.numDBs++] = hash;
    }
    return(0);
}

uint32_t ensure_ramchain_DBs(struct ramchain *ram)
{
   /* uint32_t i,j,numpurged,minblocknum,nonz,numerrs;
    struct unspent_entry *unspents;
    uint64_t sum,total;
    int64_t errtotal,balance;*/
    ram->ledger.L.blocknum = 1;
    strcpy(ram->ledger.coinstr,ram->name);
    init_hashDBs(ram,ram->name,&ram->ledger.ledgers,"ledgers","lz4");
    init_hashDBs(ram,ram->name,&ram->ledger.unspentmap,"unspentmap","lz4");
    init_hashDBs(ram,ram->name,&ram->ledger.blocks,"blocks","lz4");
    init_hashDBs(ram,ram->name,&ram->ledger.addrs,"rawaddrs","lz4");
    init_hashDBs(ram,ram->name,&ram->ledger.txids,"txids",0);
    init_hashDBs(ram,ram->name,&ram->ledger.scripts,"scripts","lz4");
    /*minblocknum = 0xffffffff;
    for (i=0; i<ram->ledger.numDBs; i++)
    {
        if ( ram->ledger.DBs[i]->minblocknum < minblocknum )
            minblocknum = ram-ledger.DBs[i]->minblocknum;
        printf("%u ",ram->ledger.DBs[i]->minblocknum);
    }
    printf("minblocknums -> %d\n",minblocknum);
    numpurged = ramchain_setblocknums(ram,minblocknum,0);
    if ( 0 && numpurged > 10 )
    {
        printf("will purge %d DB entrys. 'y' to proceed\n",numpurged);
        if ( getchar() == 'y' )
        {
            numpurged = ramchain_setblocknums(ram,minblocknum,1);
            printf("purged.%d\n",numpurged);
        } else exit(-1);
    }
    printf("finished setblocknums\n");
    getchar();
    return(minblocknum);*/
    return(0);
}

void ramchain_update(struct coin777 *coin)
{
    uint32_t blocknum;
    //printf("%s ramchain_update: ready.%d\n",coin->name,coin->ramchain.readyflag);
    if ( coin->ramchain.readyflag == 0 )
        return;
    if ( (blocknum= coin->ramchain.blocknum) < coin->ramchain.RTblocknum )
    {
        if ( blocknum == 0 )
            coin->ramchain.blocknum = blocknum = 1;
        if ( ramchain_processblock(coin,blocknum,coin->ramchain.RTblocknum) == 0 )
        {
            coin->ramchain.blocknum++;
            if ( 0 && coin->ramchain.numupdates++ > 10000 )
            {
                ramchain_syncDBs(&coin->ramchain);
                printf("Start backups\n");// getchar();
                coin->ramchain.numupdates = 0;
            }
        }
        else printf("%s error processing block.%d\n",coin->name,blocknum);
    }
}

int32_t init_ramchain(struct coin777 *coin,char *coinstr)
{
    struct ramchain *ram = &coin->ramchain;
    ram->startmilli = milliseconds();
    strcpy(ram->name,coinstr);
    ram->blocknum = ram->startblocknum = ensure_ramchain_DBs(ram);
    ram->huffallocsize = sizeof(struct rawblock)/10, ram->huffbits = calloc(1,ram->huffallocsize), ram->huffbits2 = calloc(1,ram->huffallocsize);
    ram->RTblocknum = _get_RTheight(&ram->lastgetinfo,coinstr,coin->serverport,coin->userpass,ram->RTblocknum);
    ramchain_syncDBs(ram);
    coin->ramchain.readyflag = 1;
    return(0);
}

#endif
#endif
