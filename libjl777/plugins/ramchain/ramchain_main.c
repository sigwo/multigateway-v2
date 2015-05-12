//
//  ramchain.c
//  SuperNET API extension example plugin
//  crypto777
//
//  Copyright (c) 2015 jl777. All rights reserved.
//

#define BUNDLED
#define PLUGINSTR "ramchain"
#define PLUGNAME(NAME) ramchain ## NAME
#define STRUCTNAME struct PLUGNAME(_info) 
#define STRINGIFY(NAME) #NAME
#define PLUGIN_EXTRASIZE sizeof(STRUCTNAME)

#define DEFINES_ONLY
#include "../plugin777.c"
#include "storage.c"
#include "system777.c"
#undef DEFINES_ONLY

STRUCTNAME RAMCHAINS;
char *PLUGNAME(_methods)[] = { "create", "backup", "restore" }; // list of supported methods

struct ledger_blockinfo
{
    uint16_t crc16,numtx,numaddrs,numscripts,numvouts,numvins;
    uint32_t blocknum,txidind,addrind,scriptind,unspentind,totalspends,allocsize;
    uint64_t minted;
    uint8_t transactions[];
};
struct ledger_txinfo { uint32_t firstvout,firstvin; uint16_t numvouts,numvins; uint8_t txidlen,txid[255]; };
struct ledger_spendinfo { uint32_t unspentind,spent_txidind; uint16_t spent_vout; };
struct unspentmap { uint32_t addrind; uint32_t value[2]; };
struct ledger_voutdata { struct unspentmap U; uint32_t scriptind; int32_t addrlen,scriptlen,newscript,newaddr; char coinaddr[256]; uint8_t script[256]; };

uint16_t block_crc16(struct ledger_blockinfo *block)
{
    uint32_t crc32 = _crc32(0,(void *)((long)&block->crc16 + sizeof(block->crc16)),block->allocsize - sizeof(block->crc16));
    return((crc32 >> 16) ^ (crc32 & 0xffff));
}

uint32_t ledger_packtx(uint8_t *hash,struct sha256_state *state,struct alloc_space *mem,struct ledger_txinfo *tx)
{
    int32_t allocsize;
    allocsize = sizeof(*tx) - sizeof(tx->txid) + tx->txidlen;
    memcpy(memalloc(mem,allocsize,0),tx,allocsize);
    update_sha256(hash,state,(uint8_t *)tx,allocsize);
    return(allocsize);
}

uint32_t ledger_packspend(uint8_t *hash,struct sha256_state *state,struct alloc_space *mem,struct ledger_spendinfo *spend)
{
    memcpy(memalloc(mem,sizeof(spend->unspentind),0),&spend->unspentind,sizeof(spend->unspentind));
    update_sha256(hash,state,(uint8_t *)&spend->unspentind,sizeof(spend->unspentind));
    return(sizeof(spend->unspentind));
}

uint32_t ledger_packvoutstr(struct alloc_space *mem,uint32_t rawind,int32_t newitem,uint8_t *str,uint8_t len)
{
    if ( newitem != 0 )
    {
        rawind |= (1 << 31);
        memcpy(memalloc(mem,sizeof(rawind),0),&rawind,sizeof(rawind));
        memcpy(memalloc(mem,sizeof(len),0),&len,sizeof(len));
        memcpy(memalloc(mem,len,0),str,len);
        return(sizeof(rawind) + sizeof(len) + len);
    }
    else
    {
        memcpy(memalloc(mem,sizeof(rawind),0),&rawind,sizeof(rawind));
        return(sizeof(rawind));
    }
}

uint32_t ledger_packvout(uint8_t *hash,struct sha256_state *state,struct alloc_space *mem,struct ledger_voutdata *vout)
{
    uint32_t allocsize; void *ptr;
    ptr = memalloc(mem,sizeof(vout->U.value),0);
    memcpy(ptr,&vout->U.value,sizeof(vout->U.value)), allocsize = sizeof(vout->U.value);
    allocsize += ledger_packvoutstr(mem,vout->U.addrind,vout->newaddr,(uint8_t *)vout->coinaddr,vout->addrlen);
    allocsize += ledger_packvoutstr(mem,vout->scriptind,vout->newscript,vout->script,vout->scriptlen);
    update_sha256(hash,state,ptr,allocsize);
    return(allocsize);
}

int32_t ledger_ensuretxoffsets(struct ledger_info *ledger,uint32_t numtxidinds)
{
    int32_t n,width = 4096;
    if ( numtxidinds >= ledger->txoffsets.ind )
    {
        n = ledger->txoffsets.ind + width;
        if ( Debuglevel > 2 )
            printf("realloc ledger->txoffsets.D.upairs %p %d -> %d\n",ledger->txoffsets.D.upairs,ledger->txoffsets.ind,n);
        ledger->txoffsets.D.upairs = realloc(ledger->txoffsets.D.upairs,sizeof(*ledger->txoffsets.D.upairs) * n);
        memset(&ledger->txoffsets.D.upairs[ledger->txoffsets.ind],0,width * sizeof(*ledger->txoffsets.D.upairs));
        ledger->txoffsets.ind += width;
        return(width);
    }
    return(0);
}

int32_t ledger_ensurespentbits(struct ledger_info *ledger,uint32_t totalvouts)
{
    int32_t i,n,width = 4096;
    if ( totalvouts >= ledger->spentbits.ind )
    {
        n = ledger->spentbits.ind + (width << 3);
        if ( Debuglevel > 2 )
            printf("realloc spentbits.%p %d -> %d\n",ledger->spentbits.D.bits,ledger->spentbits.ind,n);
        ledger->spentbits.D.bits = realloc(ledger->spentbits.D.bits,n + 1);
        if ( (ledger->spentbits.ind & 7) != 0 )
        {
            for (i=0; i<(width << 3); i++) // horribly inefficient, but we shouldnt have this case
                CLEARBIT(ledger->spentbits.D.bits,ledger->spentbits.ind + i);
        } else memset(&ledger->spentbits.D.bits[ledger->spentbits.ind >> 3],0,width);
        ledger->spentbits.ind = n;
        return(width);
    }
    return(0);
}

int32_t addrinfo_size(int32_t n) { return(sizeof(struct ledger_addrinfo) + (sizeof(uint32_t) * n)); }

struct ledger_addrinfo *addrinfo_update(struct ledger_addrinfo *addrinfo,char *coinaddr,int32_t addrlen,uint64_t value,uint32_t unspentind)
{
    int32_t width;
    if ( addrinfo == 0 )
    {
        addrinfo = calloc(1,addrinfo_size(1));
        if ( addrlen > sizeof(addrinfo->coinaddr) - 1 )
            printf("unexpected addrlen.%d (%s)\n",addrlen,coinaddr);
        addrinfo->max = 1, addrinfo->count = 0;
        strcpy(addrinfo->coinaddr,coinaddr);
    }
    else if ( addrinfo->count >= addrinfo->max )
    {
        width = (addrinfo->count << 1) + 1;
        if ( width > 256 )
            width = 256;
        addrinfo->max = (addrinfo->count + width);
        addrinfo = realloc(addrinfo,addrinfo_size(addrinfo->max));
        memset(&addrinfo->unspentinds[addrinfo->count],0,width * sizeof(*addrinfo->unspentinds));
    }
    addrinfo->balance += value;
    addrinfo->dirty = 1;
    addrinfo->unspentinds[addrinfo->count++] = unspentind;
    return(addrinfo);
}

struct ledger_addrinfo *ledger_ensureaddrinfos(struct ledger_info *ledger,uint32_t addrind)
{
    int32_t n,width = 4096;
    if ( addrind >= ledger->addrinfos.ind )
    {
        n = (addrind + width);
        if ( Debuglevel > 2 )
            printf("realloc addrinfos[%u] %d -> %d\n",addrind,ledger->addrinfos.ind,n);
        if ( ledger->addrinfos.D.table != 0 )
        {
            ledger->addrinfos.D.table = realloc(ledger->addrinfos.D.table,sizeof(*ledger->addrinfos.D.table) * n);
            memset(&ledger->addrinfos.D.table[ledger->addrinfos.ind],0,sizeof(*ledger->addrinfos.D.table) * (n - ledger->addrinfos.ind));
        }
        else ledger->addrinfos.D.table = calloc(width,sizeof(*ledger->addrinfos.D.table));
        ledger->addrinfos.ind += width;
    }
    return(ledger->addrinfos.D.table[addrind]);
}

uint64_t ledger_recalc_addrinfos(struct ledger_info *ledger,int32_t richlist)
{
    //char coinaddr[256];
    struct ledger_addrinfo *addrinfo;
    uint32_t i,n,addrind; float *sortbuf; uint64_t balance,addrsum;
    addrsum = n = 0;
    if ( ledger->addrinfos.D.table == 0 )
        return(0);
    if ( richlist == 0 )
    {
        for (i=1; i<=ledger->addrs.ind; i++)
            if ( (addrinfo= ledger->addrinfos.D.table[i]) != 0 && (balance= addrinfo->balance) != 0 )
                addrsum += balance;
    }
    else
    {
        sortbuf = calloc(ledger->addrs.ind,sizeof(float)+sizeof(uint32_t));
        for (i=1; i<=ledger->addrs.ind; i++)
            if ( (addrinfo= ledger->addrinfos.D.table[i]) != 0 && (balance= addrinfo->balance) != 0 )
            {
                addrsum += balance;
                sortbuf[n << 1] = dstr(balance);
                memcpy(&sortbuf[(n << 1) + 1],&i,sizeof(i));
                n++;
            }
        if ( n > 0 )
        {
            revsortfs(sortbuf,n,sizeof(*sortbuf) * 2);
            for (i=0; i<10&&i<n; i++)
            {
                memcpy(&addrind,&sortbuf[(i << 1) + 1],sizeof(addrind));
                addrinfo = ledger->addrinfos.D.table[addrind];
                //memcpy(coinaddr,addrinfo->space,addrinfo->addrlen);
                //coinaddr[addrinfo->addrlen] = 0;
                printf("(%s %.8f) ",addrinfo->coinaddr,sortbuf[i << 1]);
            }
            printf("top.%d of %d\n",i,n);
        }
        free(sortbuf);
    }
    return(addrsum);
}

uint32_t ledger_rawind(void *transactions,struct ledger_state *hash,void *key,int32_t keylen)
{
    int32_t size; uint32_t *ptr,rawind = 0;
    if ( (ptr= db777_findM(&size,hash->D.DB,key,keylen)) != 0 )
    {
        if ( size == sizeof(uint32_t) )
        {
            rawind = *ptr;
            if ( (rawind - 1) == hash->ind )
                hash->ind = rawind;
            //else printf("unexpected gap rawind.%d vs hash->ind.%d\n",rawind,hash->ind);
            //if ( hash->ind > hash->maxind )
            //    hash->maxind = hash->ind;
            //printf("found keylen.%d rawind.%d (%d %d)\n",keylen,rawind,hash->ind,hash->maxind);
        }
        else printf("error unexpected size.%d for (%s) keylen.%d\n",size,hash->name,keylen);
        free(ptr);
        return(rawind);
    }
    rawind = ++hash->ind;
    //printf("add rawind.%d keylen.%d\n",rawind,keylen);
    if ( db777_add(1,transactions,hash->D.DB,key,keylen,&rawind,sizeof(rawind)) != 0 )
        printf("error adding to %s DB for rawind.%d keylen.%d\n",hash->name,rawind,keylen);
    else
    {
        update_sha256(hash->sha256,&hash->state,key,keylen);
        return(rawind);
    }
    return(0);
}

uint32_t ledger_hexind(void *transactions,struct ledger_state *hash,uint8_t *data,int32_t *hexlenp,char *hexstr)
{
    uint32_t rawind = 0;
    *hexlenp = (int32_t)strlen(hexstr) >> 1;
    if ( *hexlenp < 255 )
    {
        decode_hex(data,*hexlenp,hexstr);
        rawind = ledger_rawind(transactions,hash,data,*hexlenp);
        //printf("hexlen.%d (%s) -> rawind.%u\n",hexlen,hexstr,rawind);
    }
    else  printf("hexlen overflow (%s) -> %d\n",hexstr,*hexlenp);
    return(rawind);
}

uint32_t has_duplicate_txid(struct ledger_info *ledger,char *coinstr,uint32_t blocknum,char *txidstr)
{
    int32_t hexlen,size; uint8_t data[256]; uint32_t *ptr;
    if ( strcmp(coinstr,"BTC") == 0 && blocknum < 200000 )
    {
        hexlen = (int32_t)strlen(txidstr) >> 1;
        if ( hexlen < 255 )
        {
            decode_hex(data,hexlen,txidstr);
            //if ( (blocknum == 91842 && strcmp(txidstr,"d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599") == 0) || (blocknum == 91880 && strcmp(txidstr,"e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468") == 0) )
            if ( (ptr= db777_findM(&size,ledger->txids.D.DB,data,hexlen)) != 0 )
            {
                printf("block.%u (%s) already exists.%u\n",blocknum,txidstr,*ptr);
                if ( size == sizeof(uint32_t) )
                    return(*ptr);
            }
        }
    }
    return(0);
}

uint32_t ledger_addtx(struct ledger_info *ledger,struct alloc_space *mem,uint32_t txidind,char *txidstr,uint32_t totalvouts,uint16_t numvouts,uint32_t totalspends,uint16_t numvins)
{
    uint32_t checkind; uint8_t txid[256]; struct ledger_txinfo tx; int32_t txidlen;
    if ( Debuglevel > 2 )
        printf("ledger_tx txidind.%d %s vouts.%d vins.%d | ledger->txoffsets.ind %d\n",txidind,txidstr,totalvouts,totalspends,ledger->txoffsets.ind);
    if ( (checkind= ledger_hexind(ledger->DBs.transactions,&ledger->txids,txid,&txidlen,txidstr)) == txidind )
    {
        memset(&tx,0,sizeof(tx));
        tx.firstvout = totalvouts, tx.firstvin = totalspends, tx.numvouts = numvouts, tx.numvins = numvins;
        tx.txidlen = txidlen, memcpy(tx.txid,txid,txidlen);
        ledger_ensuretxoffsets(ledger,txidind+1);
        ledger_ensurespentbits(ledger,totalvouts + numvouts);
        ledger->txoffsets.D.upairs[txidind].firstvout = totalvouts, ledger->txoffsets.D.upairs[txidind].firstvin = totalspends;
        ledger->txoffsets.D.upairs[txidind+1].firstvout = (totalvouts + numvouts), ledger->txoffsets.D.upairs[txidind+1].firstvin = (totalspends + numvins);
        return(ledger_packtx(ledger->txoffsets.sha256,&ledger->txoffsets.state,mem,&tx));
    } else printf("ledger_tx: mismatched txidind, expected %u got %u\n",txidind,checkind);
    while ( 1 ) sleep(1);
    return(0);
}

uint32_t ledger_addunspent(uint16_t *numaddrsp,uint16_t *numscriptsp,struct ledger_info *ledger,struct alloc_space *mem,uint32_t txidind,uint16_t v,uint32_t unspentind,char *coinaddr,char *scriptstr,uint64_t value)
{
    struct ledger_voutdata vout;
    memset(&vout,0,sizeof(vout));
    memcpy(vout.U.value,&value,sizeof(vout.U.value));
    ledger->voutsum += value;
    //printf("%.8f ",dstr(value));
    if ( (vout.scriptind= ledger_hexind(ledger->DBs.transactions,&ledger->scripts,vout.script,&vout.scriptlen,scriptstr)) == 0 )
    {
        printf("ledger_unspent: error getting scriptind.(%s)\n",scriptstr);
        return(0);
    }
    vout.newscript = (vout.scriptind == ledger->scripts.ind);
    (*numscriptsp) += vout.newscript;
    vout.addrlen = (int32_t)strlen(coinaddr);
    if ( (vout.U.addrind= ledger_rawind(ledger->DBs.transactions,&ledger->addrs,coinaddr,vout.addrlen)) != 0 )
    {
        ledger->unspentmap.ind = unspentind;
        if ( db777_add(0,ledger->DBs.transactions,ledger->unspentmap.D.DB,&unspentind,sizeof(unspentind),&vout.U,sizeof(vout.U)) != 0 )
            printf("error saving unspentmap (%s) %u -> %u %.8f\n",ledger->DBs.coinstr,unspentind,vout.U.addrind,dstr(value));
        if ( vout.U.addrind == ledger->addrs.ind )
            vout.newaddr = 1, strcpy(vout.coinaddr,coinaddr), (*numaddrsp)++;
        if ( Debuglevel > 2 )
            printf("txidind.%u v.%d unspent.%d (%s).%u (%s).%u %.8f | %ld\n",txidind,v,unspentind,coinaddr,vout.U.addrind,scriptstr,vout.scriptind,dstr(value),sizeof(vout.U));
        ledger_ensureaddrinfos(ledger,vout.U.addrind);
        ledger->addrinfos.D.table[vout.U.addrind] = addrinfo_update(ledger->addrinfos.D.table[vout.U.addrind],coinaddr,vout.addrlen,value,unspentind);
         return(ledger_packvout(ledger->addrinfos.sha256,&ledger->addrinfos.state,mem,&vout));
    } else printf("ledger_unspent: cant find addrind.(%s)\n",coinaddr);
    return(0);
}

uint32_t ledger_addspend(struct ledger_info *ledger,struct alloc_space *mem,uint32_t spend_txidind,uint32_t totalspends,char *spent_txidstr,uint16_t vout)
{
    struct ledger_spendinfo spend;
    int32_t i,n,size,txidlen,addrind; uint64_t value; uint32_t spent_txidind; uint8_t txid[256];
    struct ledger_addrinfo *addrinfo; struct unspentmap *U;
    //printf("spend_txidind.%d totalspends.%d (%s).v%d\n",spend_txidind,totalspends,spent_txidstr,vout);
    if ( (spent_txidind= ledger_hexind(ledger->DBs.transactions,&ledger->txids,txid,&txidlen,spent_txidstr)) != 0 )
    {
        memset(&spend,0,sizeof(spend));
        spend.spent_txidind = spent_txidind, spend.spent_vout = vout;
        spend.unspentind = ledger->txoffsets.D.upairs[spent_txidind].firstvout + vout;
        SETBIT(ledger->spentbits.D.bits,spend.unspentind);
        if ( (U= db777_findM(&size,ledger->unspentmap.D.DB,&spend.unspentind,sizeof(spend.unspentind))) == 0 || size != sizeof(*U) )
        {
            if ( U != 0 )
                free(U);
            for (i=spent_txidind-100; i<=spent_txidind; i++)
                if ( i >= 0 )
                    printf("%d.(%d %d) ",i,ledger->txoffsets.D.upairs[i].firstvout,ledger->txoffsets.D.upairs[i].firstvin);
            printf("error loading unspentmap (%s) unspentind.%u | txidind.%d vout.%d\n",ledger->DBs.coinstr,spend.unspentind,spent_txidind,vout);
            return(0);
        }
        memcpy(&value,U->value,sizeof(value)), addrind = U->addrind, free(U);
        ledger->spendsum += value;
        if ( (addrinfo= ledger_ensureaddrinfos(ledger,addrind)) == 0 )
        {
            printf("null addrinfo for addrind.%d max.%d, unspentind.%d %.8f\n",addrind,ledger->addrs.ind,spend.unspentind,dstr(value));
            return(0);
        }
        if ( (n= addrinfo->count) > 0 )
        {
            for (i=0; i<n; i++)
            {
                if ( spend.unspentind == addrinfo->unspentinds[i] )
                {
                    addrinfo->balance -= value;
                    addrinfo->dirty = 1;
                    addrinfo->unspentinds[i] = addrinfo->unspentinds[--addrinfo->count];
                    addrinfo->unspentinds[addrinfo->count] = 0;
                    if ( (addrinfo->count == 0 && addrinfo->balance != 0) || addrinfo->count < 0 )
                    {
                        printf("ILLEGAL: addrind.%u count.%d max.%d %.8f\n",addrind,addrinfo->count,addrinfo->max,dstr(addrinfo->balance));
                        getchar();
                    }
                    if ( Debuglevel > 2 )
                        printf("addrind.%u count.%d max.%d %.8f\n",addrind,addrinfo->count,addrinfo->max,dstr(addrinfo->balance));
                    break;
                }
            }
            if ( i == n )
            {
                printf("addrind.%u cant find unspentind.%u for (%s).%u v%d\n",addrind,spend.unspentind,spent_txidstr,spend_txidind,vout);
                getchar();
                return(0);
            }
        }
        return(ledger_packspend(ledger->spentbits.sha256,&ledger->spentbits.state,mem,&spend));
    } else printf("ledger_spend: cant find txidind for (%s).v%d\n",spent_txidstr,vout);
    return(0);
}

struct ledger_blockinfo *ledger_startblock(struct ledger_info *ledger,struct alloc_space *mem,uint32_t blocknum,uint64_t minted,int32_t numtx)
{
    struct ledger_blockinfo *block;
    if ( ledger->blockpending != 0 )
    {
        printf("ledger_startblock: cant startblock when %s %u is pending\n",ledger->DBs.coinstr,ledger->blocknum);
        return(0);
    }
    ledger->blockpending = 1, ledger->blocknum = blocknum;
    block = memalloc(mem,sizeof(*block),1);
    block->blocknum = blocknum, block->minted = minted, block->numtx = numtx;
    block->txidind = ledger->txids.ind + 1, block->addrind = ledger->addrs.ind + 1, block->scriptind = ledger->scripts.ind + 1;
    block->unspentind = ledger->unspentmap.ind + 1, block->totalspends = ledger->spentbits.ind + 1;
    ledger->DBs.transactions = sp_begin(ledger->DBs.env);
    return(block);
}

int32_t ledger_commitblock(struct ledger_info *ledger,struct alloc_space *mem,struct ledger_blockinfo *block)
{
    int32_t err;
    if ( ledger->blockpending == 0 || ledger->blocknum != block->blocknum )
    {
        printf("ledger_commitblock: mismatched parameter pending.%d (%d %d)\n",ledger->blockpending,ledger->blocknum,block->blocknum);
        return(0);
    }
    ledger->blocknum++;
    while ( ledger->DBs.transactions != 0 && (err= sp_commit(ledger->DBs.transactions)) != 0 )
    {
        printf("ledger_commitblock: sp_commit error.%d\n",err);
        if ( err < 0 )
        {
            ledger->DBs.transactions = 0;
            return(-1);
        }
        msleep(1000);
    }
    ledger->DBs.transactions = 0;
     //ledger->addrind = ledger->addrs.ind, ledger->scriptind = ledger->scripts.ind;
    block->allocsize = (uint32_t)mem->used;
    block->crc16 = block_crc16(block);
    if ( Debuglevel > 2 )
        printf("block.%u mem.%p size.%d crc.%u\n",block->blocknum,mem,block->allocsize,block->crc16);
    if ( db777_add(-1,ledger->DBs.transactions,ledger->blocks.D.DB,&block->blocknum,sizeof(block->blocknum),block,block->allocsize) != 0 )
    {
        printf("error saving blocks %s %u\n",ledger->DBs.coinstr,block->blocknum);
        return(0);
    }
    ledger->blockpending = 0;
    return(block->allocsize);
}

struct ledger_blockinfo *ledger_update(int32_t dispflag,struct ledger_info *ledger,struct alloc_space *mem,struct coin777 *coin,struct rawblock *emit,uint32_t blocknum)
{
    struct rawtx *tx; struct rawvin *vi; struct rawvout *vo; struct ledger_blockinfo *block = 0;
    uint32_t i,txidind,txind,n;
    if ( rawblock_load(emit,coin->name,coin->serverport,coin->userpass,blocknum) > 0 )
    {
        tx = emit->txspace, vi = emit->vinspace, vo = emit->voutspace;
        block = ledger_startblock(ledger,mem,blocknum,emit->minted,emit->numtx);
        if ( block->numtx > 0 )
        {
            for (txind=0; txind<block->numtx; txind++,tx++)
            {
                if ( (txidind= has_duplicate_txid(ledger,ledger->DBs.coinstr,blocknum,tx->txidstr)) == 0 )
                    txidind = ledger->txids.ind + 1;
                //printf("expect txidind.%d unspentind.%d totalspends.%d\n",txidind,block->unspentind+1,block->totalspends);
                ledger_addtx(ledger,mem,txidind,tx->txidstr,ledger->unspentmap.ind+1,tx->numvouts,ledger->spentbits.ind+1,tx->numvins);
                if ( (n= tx->numvouts) > 0 )
                    for (i=0; i<n; i++,vo++,block->numvouts++)
                        ledger_addunspent(&block->numaddrs,&block->numscripts,ledger,mem,txidind,i,++ledger->unspentmap.ind,vo->coinaddr,vo->script,vo->value);
                if ( (n= tx->numvins) > 0 )
                    for (i=0; i<n; i++,vi++,block->numvins++)
                        ledger_addspend(ledger,mem,txidind,++ledger->spentbits.ind,vi->txidstr,vi->vout);
            }
        }
        db777_add(1,ledger->DBs.transactions,ledger->blocks.D.DB,"latest",strlen("latest"),&ledger->blocknum,sizeof(ledger->blocknum));
    } else printf("error loading %s block.%u\n",coin->name,blocknum);
    return(block);
}

int32_t ledger_compare(struct ledger_info *ledgerA,struct ledger_info *ledgerB)
{
    int32_t i,n; struct ledger_addrinfo *addrA,*addrB;
    if ( ledgerA != 0 && ledgerB != 0 )
    {
        if ( ledgerA->txoffsets.D.upairs == 0 || ledgerB->txoffsets.D.upairs == 0 || (n= ledgerA->txoffsets.ind) != ledgerB->txoffsets.ind )
            return(-1);
        if ( memcmp(ledgerA->txoffsets.D.upairs,ledgerB->txoffsets.D.upairs,n * sizeof(*ledgerA->txoffsets.D.upairs)) != 0 )
            return(-2);
        if ( ledgerA->spentbits.D.bits == 0 || ledgerB->spentbits.D.bits == 0 || (n= ledgerA->spentbits.ind) != ledgerB->spentbits.ind )
            return(-3);
        if ( memcmp(ledgerA->spentbits.D.bits,ledgerB->spentbits.D.bits,(n >> 3) + 1) != 0 )
            return(-4);
        if ( ledgerA->addrinfos.D.table == 0 || ledgerB->addrinfos.D.table == 0 || (n= ledgerA->addrinfos.ind) != ledgerB->addrinfos.ind )
            return(-5);
        for (i=0; i<n; i++)
        {
            if ( ((addrA= ledgerA->addrinfos.D.table[i]) != 0) != ((addrB= ledgerB->addrinfos.D.table[i]) != 0) )
                return(-6 - i*3);
            if ( addrA != 0 && addrB != 0 )
            {
                if ( addrA->count != addrB->count )
                    return(-6 - i*3 - 1);
                if ( memcmp(addrA,addrB,addrinfo_size(addrA->count)) != 0 )
                {
                    int32_t j,m = addrinfo_size(addrA->count);
                    for (j=0; j<m; j++)
                        printf("%02x ",((uint8_t *)ledgerA->addrinfos.D.table[i])[j]);
                    printf("A\n");
                    for (j=0; j<m; j++)
                        printf("%02x ",((uint8_t *)ledgerB->addrinfos.D.table[i])[j]);
                    printf("B\n");
                    return(-6 - i*3 - 2);
                }
            }
        }
        return(0);
    }
    return(-1);
}

#define LEDGER_DB_CLOSE 1
#define LEDGER_DB_BACKUP 2
#define LEDGER_DB_UPDATE 3

int32_t ledger_DBopcode(void *ctl,struct db777 *DB,int32_t opcode)
{
    int32_t retval = -1;
    if ( opcode == LEDGER_DB_CLOSE )
    {
        retval = sp_destroy(DB->db);
        DB->db = DB->asyncdb = 0;
    }
    return(retval);
}

int32_t ledger_DBopcodes(struct env777 *DBs,int32_t opcode)
{
    int32_t i,lastbackup,numerrs = 0;
    if ( opcode == LEDGER_DB_BACKUP || (opcode == LEDGER_DB_UPDATE && DBs->needbackup != 0) )
    {
        return(db777_backup(DBs->ctl));
        DBs->needbackup = 1;
        lastbackup = (int32_t)db777_ctlinfo64(DBs->ctl,"backup.last");
        if ( db777_ctlinfo64(DBs->ctl,"backup.active") == 0 )
        {
            if ( db777_ctlinfo64(DBs->ctl,"backup.last_complete") != 0 )
                printf("DB.(%s) backup.%d not complete\n",DBs->subdir,lastbackup);
            else
            {
                printf("DB.(%s) backup.%d complete, start next backup\n",DBs->subdir,lastbackup);
                DBs->lastbackup = lastbackup;
                DBs->currentbackup = (lastbackup + 1);
                DBs->needbackup = 0;
                return(db777_backup(DBs->ctl));
            }
        } else printf("DB.(%s) backup.%d still active\n",DBs->subdir,lastbackup);
    }
    else
    {
        for (i=0; i<DBs->numdbs; i++)
            numerrs += (ledger_DBopcode(DBs->ctl,&DBs->dbs[i],opcode) != 0);
    }
    return(numerrs);
}

void ledger_free(struct ledger_info *ledger,int32_t closeDBflag)
{
    int32_t i;
    if ( ledger != 0 )
    {
        if ( ledger->txoffsets.D.upairs != 0 )
            free(ledger->txoffsets.D.upairs);
        if ( ledger->spentbits.D.bits != 0 )
            free(ledger->spentbits.D.bits);
        if ( ledger->addrinfos.D.table != 0 )
        {
            for (i=0; i<ledger->addrinfos.ind; i++)
                if ( ledger->addrinfos.D.table[i] != 0 )
                    free(ledger->addrinfos.D.table[i]);
            free(ledger->addrinfos.D.table);
        }
        if ( closeDBflag != 0 )
            ledger_DBopcodes(&ledger->DBs,LEDGER_DB_CLOSE);
        free(ledger);
    }
}

void ledger_stateinit(struct env777 *DBs,struct ledger_state *sp,char *coinstr,char *subdir,char *name,char *compression)
{
    safecopy(sp->name,name,sizeof(sp->name));
    update_sha256(sp->sha256,&sp->state,0,0);
    if ( DBs != 0 )
        sp->D.DB = db777_open(0,DBs,name,compression);
}

struct ledger_info *ledger_alloc(char *coinstr,char *subdir)
{
    struct ledger_info *ledger = 0;
    if ( (ledger= calloc(1,sizeof(*ledger))) != 0 )
    {
        safecopy(ledger->DBs.coinstr,coinstr,sizeof(ledger->DBs.coinstr));
        safecopy(ledger->DBs.subdir,subdir,sizeof(ledger->DBs.subdir));
        ledger_stateinit(0,&ledger->txoffsets,coinstr,0,"txoffsets",0);
        ledger_stateinit(0,&ledger->spentbits,coinstr,0,"spentbits",0);
        ledger_stateinit(0,&ledger->addrinfos,coinstr,0,"addrinfos",0);
        
        ledger_stateinit(&ledger->DBs,&ledger->blocks,coinstr,subdir,"blocks","zstd");
        ledger_stateinit(&ledger->DBs,&ledger->ledger,coinstr,subdir,"ledger","zstd");
        ledger_stateinit(&ledger->DBs,&ledger->addrs,coinstr,subdir,"addrs","zstd");
        ledger_stateinit(&ledger->DBs,&ledger->txids,coinstr,subdir,"txids",0);
        ledger_stateinit(&ledger->DBs,&ledger->scripts,coinstr,subdir,"scripts","zstd");
        ledger_stateinit(&ledger->DBs,&ledger->unspentmap,coinstr,subdir,"unspentmap","zstd");
        ledger->blocknum = 1;
    }
    return(ledger);
}

int32_t ledger_save(struct ledger_info *ledger)
{
    uint32_t addrind,allocsize,dirty = 0; struct ledger_addrinfo *addrinfo;
    if ( ledger->txoffsets.D.upairs == 0 || ledger->spentbits.D.bits == 0 || ledger->addrinfos.D.table == 0 )
    {
        printf("uninitialized pointer %p %p %p\n",ledger->txoffsets.D.upairs,ledger->spentbits.D.bits,ledger->addrinfos.D.table);
        return(-1);
    }
    if ( db777_add(1,ledger->DBs.transactions,ledger->ledger.D.DB,"ledger",strlen("ledger"),ledger,sizeof(*ledger)) == 0 )
        printf("error saving ledger\n");
    else if ( db777_add(1,ledger->DBs.transactions,ledger->ledger.D.DB,"txoffsets",strlen("txoffsets"),ledger->txoffsets.D.upairs,(int32_t)(ledger->txoffsets.ind * sizeof(*ledger->txoffsets.D.upairs))) == 0 )
        printf("error saving txoffsets\n");
    else if ( db777_add(1,ledger->DBs.transactions,ledger->ledger.D.DB,"spentbits",strlen("spentbits"),ledger->spentbits.D.bits,(ledger->spentbits.ind >> 3) + 1) == 0 )
        printf("error saving spentbits\n");
    else
    {
        allocsize = (uint32_t)(sizeof(*ledger) + (ledger->txoffsets.ind * sizeof(*ledger->txoffsets.D.upairs)) + ((ledger->spentbits.ind >> 3) + 1));
        for (addrind=1; addrind<=ledger->addrs.ind; addrind++)
        {
            if ( (addrinfo= ledger->addrinfos.D.table[addrind]) != 0 && addrinfo->dirty != 0 )
            {
                dirty++;
                addrinfo->dirty = 0;
                if ( db777_add(1,ledger->DBs.transactions,ledger->ledger.D.DB,&addrind,sizeof(addrind),addrinfo,addrinfo_size(addrinfo->count)) == 0 )
                {
                    printf("error saving addrinfo[%u]\n",addrind);
                    return(-1);
                }
                else allocsize += addrinfo_size(addrinfo->count);
            }
        }
        printf("  [sync'ed %d addrinfos, saved %d bytes %s] ",dirty,allocsize,_mbstr(allocsize));
        ledger_DBopcodes(&ledger->DBs,LEDGER_DB_BACKUP);
        return(dirty);
    }
    return(-1);
}

void _ledger_clearDBs(struct ledger_info *ledger)
{
    ledger->ledger.D.DB = ledger->addrs.D.DB = ledger->txids.D.DB = ledger->scripts.D.DB = ledger->unspentmap.D.DB = ledger->blocks.D.DB = 0;
}

struct ledger_info *_ledger_load(struct db777 *ledgerDB)
{
    int32_t len; uint32_t addrind,allocsize; struct ledger_info *ledger;
    if ( (ledger= db777_findM(&len,ledgerDB,"ledger",strlen("ledger"))) == 0 || len != sizeof(*ledger) )
        printf("error loading ledger len.%d vs %ld\n",len,sizeof(ledger));
    else if ( (ledger->txoffsets.D.upairs= db777_findM(&len,ledgerDB,"txoffsets",strlen("txoffsets"))) == 0 || len != (ledger->txoffsets.ind * sizeof(*ledger->txoffsets.D.upairs)) )
        printf("error loading txoffsets len.%d vs %ld\n",len,(ledger->txoffsets.ind * sizeof(*ledger->txoffsets.D.upairs)));
    else if ( (ledger->spentbits.D.bits=db777_findM(&len,ledgerDB,"spentbits",strlen("spentbits"))) == 0 || len != ((ledger->spentbits.ind >> 3) + 1) )
        printf("error loading spentbits len.%d vs %d\n",len,((ledger->spentbits.ind >> 3) + 1));
    else
    {
        allocsize = (uint32_t)(sizeof(*ledger) + (ledger->txoffsets.ind * sizeof(*ledger->txoffsets.D.upairs)) + ((ledger->spentbits.ind >> 3) + 1));
        ledger->addrinfos.D.table = calloc(ledger->addrinfos.ind,sizeof(*ledger->addrinfos.D.table));
        for (addrind=1; addrind<=ledger->addrs.ind; addrind++)
        {
            if ( (ledger->addrinfos.D.table[addrind]= db777_findM(&len,ledgerDB,&addrind,sizeof(addrind))) == 0 || len != addrinfo_size(ledger->addrinfos.D.table[addrind]->count) )
            {
                printf("error loading addrinfo[%u] len.%d vs %d\n",addrind,len,addrinfo_size(ledger->addrinfos.D.table[addrind]->count));
                ledger_free(ledger,0);
                return(0);
            }
            allocsize += addrinfo_size(ledger->addrinfos.D.table[addrind]->count);
        }
        printf("  [loaded %d bytes %s] ",allocsize,_mbstr(allocsize));
        _ledger_clearDBs(ledger);
        ledger->ledger.D.DB = ledgerDB;
        return(ledger);
    }
    return(0);
}

struct ledger_info *ledger_load(struct ramchain *ram,int32_t backupind)
{
  /*  int32_t n = 0; struct ledger_info *restore,*ledger = &ram->restoreL;
    if ( (ledger->ledger.D.DB= db777_restorebackup(ram->L.ledger.D.DB,backupind)) != 0 )
    {
        if ( (restore= _ledger_load(ledger->ledger.D.DB)) != 0 )
        {
            n++;
            if ( (ledger->addrs.D.DB= db777_restorebackup(ram->L.addrs.D.DB,backupind)) != 0 )
                n++, ledger->addrs.ind = ledger->addrind;
            if ( (ledger->txids.D.DB = db777_restorebackup(ram->L.txids.D.DB,backupind)) != 0 )
                n++, ledger->txids.ind = ledger->txidind;
            if ( (ledger->scripts.D.DB = db777_restorebackup(ram->L.scripts.D.DB,backupind)) != 0 )
                n++, ledger->scripts.ind = ledger->scriptind;
            if ( (ledger->unspentmap.D.DB = db777_restorebackup(ram->L.unspentmap.D.DB,backupind)) != 0 )
                n++;
            if ( (ledger->blocks.D.DB = db777_restorebackup(ram->L.blocks.D.DB,backupind)) != 0 )
                n++;
            printf("restoreL %p: restored blocknum.%u txidind.%u addrind.%u scriptind.%u uspentind.%u totalspends.%u\n",ledger,ledger->blocknum + 1,ledger->txidind,ledger->addrind,ledger->scriptind,ledger->totalvouts,ledger->spentbits.ind);
            if ( n != 6 )
                ledger_free(ledger,1), ledger = 0;
            else
            {
                ledger->blocknum++;
            }
        }
    }
    return(ledger);*/
    if ( backupind == 0 )
    {
        
    }
    return(0);
}

int32_t ledger_backup(struct ramchain *ram,struct ledger_info *ledger)
{
    struct ledger_info *backup; int32_t retval = -100;
    if ( (retval= ledger_save(ledger)) > 0 )
    {
        if ( (backup= ledger_load(ram,0)) != 0 )
        {
            if ( (retval= ledger_compare(ledger,backup)) < 0 )
                printf("ledger miscompared.%d backup %s %d\n",retval,backup->DBs.coinstr,backup->blocknum);
            else
            {
                printf("ledger compared!\n");
            }
            ledger_free(backup,0);
        }
    }
    return(retval);
}

void ramchain_update(struct coin777 *coin)
{
    struct alloc_space MEM; struct ledger_info *ledger; struct ledger_blockinfo *block; struct ramchain *ram = &coin->ramchain;
    int32_t lastbackup,allocsize; uint32_t blocknum,syncflag,dispflag; uint64_t supply,oldsupply; double estimate,elapsed;
    if ( coin->ramchain.readyflag == 0 || (ledger= coin->ramchain.activeledger) == 0 )
        return;
    if ( (blocknum= ledger->blocknum) < coin->ramchain.RTblocknum )
    {
        if ( blocknum == 0 )
            ledger->blocknum = blocknum = 1;
        syncflag = 2 * (((blocknum % coin->ramchain.backupfreq) == (coin->ramchain.backupfreq-1)) || (ram->needbackup != 0));
        dispflag = 1 || (blocknum > ram->RTblocknum - 1000);
        dispflag += ((blocknum % 100) == 0);
        oldsupply = ledger->voutsum - ledger->spendsum;
        if ( (blocknum % 1000) == 0 || (ram->RTblocknum - blocknum) < 1000 )
            ram->RTblocknum = _get_RTheight(&ram->lastgetinfo,coin->name,coin->serverport,coin->userpass,ram->RTblocknum);
        memset(&MEM,0,sizeof(MEM)), MEM.ptr = &ram->DECODE, MEM.size = sizeof(ram->DECODE);
        if ( (block= ledger_update(dispflag,ledger,&MEM,coin,&ram->EMIT,blocknum)) != 0 )
        {
            if ( syncflag != 0 )
            {
                if ( (lastbackup= ledger_backup(ram,ledger)) >= 0 )
                    ram->needbackup = 0, ram->lastbackup = lastbackup;
            }
            if ( (allocsize= ledger_commitblock(ledger,&MEM,block)) <= 0 )
                printf("error updating %s block.%u\n",coin->name,blocknum);
            ram->addrsum = ledger_recalc_addrinfos(ledger,dispflag - 1);
            ram->totalsize += block->allocsize;
            //ledger_DBopcodes(&ledger->DBs,LEDGER_DB_UPDATE);
            estimate = estimate_completion(ram->startmilli,blocknum-ram->startblocknum,ram->RTblocknum-blocknum)/60000;
            elapsed = (milliseconds()-ram->startmilli)/60000.;
            supply = ledger->voutsum - ledger->spendsum;
            if ( dispflag != 0 )
                printf("%-5s [lag %-5d] %-6u supply %.8f %.8f (%.8f) [%.8f] %.8f | dur %.2f %.2f %.2f | len.%-5d %s %.1f ave %ld sync.%d\n",coin->name,ram->RTblocknum-blocknum,blocknum,dstr(supply),dstr(ram->addrsum),dstr(supply)-dstr(ram->addrsum),dstr(supply)-dstr(oldsupply),dstr(ram->EMIT.minted),elapsed,estimate,elapsed+estimate,block->allocsize,_mbstr(ram->totalsize),(double)ram->totalsize/blocknum,sizeof(struct ledger_addrinfo),syncflag);
        }
        else printf("%s error processing block.%d\n",coin->name,blocknum);
    }
}

void ramchain_idle(struct plugin_info *plugin)
{
    int32_t i,idlei = -1;
    struct coin777 *coin,*best = 0;
    double now,age,maxage = 0.;
    if ( RAMCHAINS.num <= 0 )
        return;
    now = milliseconds();
    for (i=0; i<RAMCHAINS.num; i++)
    {
        if ( (age= (now - RAMCHAINS.lastupdate[i])) > maxage && (coin= coin777_find(RAMCHAINS.coins[i])) != 0 )
        {
            best = coin;
            idlei = i;
            maxage = age;
        }
    }
    if ( best != 0 )
    {
        ramchain_update(best);
        RAMCHAINS.lastupdate[idlei] = milliseconds();
    }
}

int32_t init_ramchain(struct coin777 *coin,char *coinstr,int32_t backupfreq)
{
    struct ramchain *ram = &coin->ramchain;
    if ( backupfreq <= 0 )
        backupfreq = 100000;
    ram->backupfreq = backupfreq;
    ram->startmilli = milliseconds();
    strcpy(ram->name,coinstr);
    ram->RTblocknum = _get_RTheight(&ram->lastgetinfo,coinstr,coin->serverport,coin->userpass,ram->RTblocknum);
    coin->ramchain.readyflag = 1;
    ram->activeledger = ledger_alloc(coinstr,"");
    env777_start(1,&ram->activeledger->DBs);
    return(0);
}

struct coin777 *ramchain_create(char *retbuf,char *coinstr)
{
    int32_t i; struct coin777 *coin;
    if ( RAMCHAINS.num > 0 )
    {
        for (i=0; i<RAMCHAINS.num; i++)
            if ( strcmp(coinstr,RAMCHAINS.coins[i]) == 0 )
                break;
    } else i = 0;
    if ( i == RAMCHAINS.num )
    {
        if ( (coin= coin777_find(coinstr)) == 0 )
            strcpy(retbuf,"{\"error\":\"cant create ramchain without coin daemon setup\"}");
        else
        {
            if ( coin->ramchain.name[0] == 0 )
            {
                if ( RAMCHAINS.num < (int32_t)(sizeof(RAMCHAINS.coins)/sizeof(*RAMCHAINS.coins)) )
                {
                    strcpy(RAMCHAINS.coins[RAMCHAINS.num++],coinstr);
                    return(coin);
                }
                else
                {
                    strcpy(retbuf,"{\"error\":\"cant create anymore ramchains, full\"}");
                    return(0);
                }
            }
        }
    }
    strcpy(retbuf,"{\"result\":\"ramchain already exists\"}");
    return(0);
}

int32_t PLUGNAME(_process_json)(struct plugin_info *plugin,uint64_t tag,char *retbuf,int32_t maxlen,char *jsonstr,cJSON *json,int32_t initflag)
{
    char *coinstr,*resultstr,*methodstr;
    struct coin777 *coin;
    struct ramchain *ram;
    int32_t backupind;
    retbuf[0] = 0;
    printf("<<<<<<<<<<<< INSIDE PLUGIN! process %s\n",plugin->name);
    if ( initflag > 0 )
    {
        strcpy(retbuf,"{\"result\":\"initflag > 0\"}");
        plugin->allowremote = 0;
        copy_cJSON(RAMCHAINS.pullnode,cJSON_GetObjectItem(json,"pullnode"));
        RAMCHAINS.readyflag = 1;
    }
    else
    {
        if ( plugin_result(retbuf,json,tag) > 0 )
            return((int32_t)strlen(retbuf));
        resultstr = cJSON_str(cJSON_GetObjectItem(json,"result"));
        methodstr = cJSON_str(cJSON_GetObjectItem(json,"method"));
        coinstr = cJSON_str(cJSON_GetObjectItem(json,"coin"));
        if ( methodstr == 0 || methodstr[0] == 0 )
        {
            printf("(%s) has not method\n",jsonstr);
            return(0);
        }
        printf("RAMCHAIN.(%s) for (%s)\n",methodstr,coinstr!=0?coinstr:"");
        if ( resultstr != 0 && strcmp(resultstr,"registered") == 0 )
        {
            plugin->registered = 1;
            strcpy(retbuf,"{\"result\":\"activated\"}");
        }
        else
        {
            if ( strcmp(methodstr,"backup") == 0 )
            {
                if ( coinstr != 0 && (coin= coin777_find(coinstr)) != 0 )
                {
                    if ( coin->ramchain.readyflag != 0 )
                    {
                        coin->ramchain.needbackup = 1;
                        strcpy(retbuf,"{\"result\":\"queued backup\"}");
                    } else strcpy(retbuf,"{\"error\":\"cant create ramchain when coin not ready\"}");
                }
                else strcpy(retbuf,"{\"error\":\"cant find coin\"}");
            }
            else if ( strcmp(methodstr,"restore") == 0 )
            {
                if ( coinstr != 0 && (coin= coin777_find(coinstr)) != 0 && ramchain_create(retbuf,coinstr) >= 0 )
                {
                    ram = &coin->ramchain;
                    if ( (backupind= get_API_int(cJSON_GetObjectItem(json,"backupind"),0)) > 0 )
                    {
                        if ( (ram->activeledger= ledger_load(ram,backupind)) != 0 )
                            strcpy(retbuf,"{\"result\":\"restore activated\"}");
                        else strcpy(retbuf,"{\"error\":\"error loading backup\"}");
                    } else strcpy(retbuf,"{\"error\":\"illegal backupind\"}");
                } else strcpy(retbuf,"{\"error\":\"cant restore ramchain when coin not ready\"}");
            }
            else if ( strcmp(methodstr,"create") == 0 )
            {
                if ( RAMCHAINS.num >= MAX_RAMCHAINS )
                    strcpy(retbuf,"{\"error\":\"cant create any more ramchains\"}");
                else if ( (coin= ramchain_create(retbuf,coinstr)) != 0 )
                    init_ramchain(coin,coin->name,get_API_int(cJSON_GetObjectItem(json,"backupfreq"),100000));
            }
        }
    }
    return((int32_t)strlen(retbuf));
}

uint64_t PLUGNAME(_register)(struct plugin_info *plugin,STRUCTNAME *data,cJSON *argjson)
{
    uint64_t disableflags = 0;
    plugin->sleepmillis = 1;
    printf("init %s size.%ld\n",plugin->name,sizeof(struct ramchain_info));
    return(disableflags); // set bits corresponding to array position in _methods[]
}

int32_t PLUGNAME(_shutdown)(struct plugin_info *plugin,int32_t retcode)
{
    if ( retcode == 0 )  // this means parent process died, otherwise _process_json returned negative value
    {
    }
    return(retcode);
}
#include "../plugin777.c"
