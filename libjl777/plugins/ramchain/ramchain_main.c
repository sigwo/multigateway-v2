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
#include "coins777.c"
#undef DEFINES_ONLY

STRUCTNAME RAMCHAINS;
char *PLUGNAME(_methods)[] = { "create", "backup" }; // list of supported methods

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
    if ( numtxidinds >= ledger->numtxoffsets )
    {
        n = ledger->numtxoffsets + width;
        if ( Debuglevel > 2 )
            printf("realloc ledger->txoffsets %p %d -> %d\n",ledger->txoffsets,ledger->numtxoffsets,n);
        ledger->txoffsets = realloc(ledger->txoffsets,sizeof(*ledger->txoffsets) * n);
        memset(&ledger->txoffsets[ledger->numtxoffsets],0,width * sizeof(*ledger->txoffsets));
        ledger->numtxoffsets += width;
        return(width);
    }
    return(0);
}

int32_t ledger_ensurespentbits(struct ledger_info *ledger,uint32_t totalvouts)
{
    int32_t i,n,width = 4096;
    if ( totalvouts >= ledger->numspentbits )
    {
        n = ledger->numspentbits + (width << 3);
        if ( Debuglevel > 2 )
            printf("realloc spentbits.%p %d -> %d\n",ledger->spentbits,ledger->numspentbits,n);
        ledger->spentbits = realloc(ledger->spentbits,n + 1);
        if ( (ledger->numspentbits & 7) != 0 )
        {
            for (i=0; i<(width << 3); i++) // horribly inefficient, but we shouldnt have this case
                CLEARBIT(ledger->spentbits,ledger->numspentbits + i);
        } else memset(&ledger->spentbits[ledger->numspentbits >> 3],0,width);
        ledger->numspentbits = n;
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
    if ( addrind >= ledger->numaddrinfos )
    {
        n = (addrind + width);
        if ( Debuglevel > 2 )
            printf("realloc addrinfos[%u] %d -> %d\n",addrind,ledger->numaddrinfos,n);
        if ( ledger->addrinfos != 0 )
        {
            ledger->addrinfos = realloc(ledger->addrinfos,sizeof(*ledger->addrinfos) * n);
            memset(&ledger->addrinfos[ledger->numaddrinfos],0,sizeof(*ledger->addrinfos) * (n - ledger->numaddrinfos));
        }
        else ledger->addrinfos = calloc(width,sizeof(*ledger->addrinfos));
        ledger->numaddrinfos += width;
    }
    return(ledger->addrinfos[addrind]);
}

void ledger_recalc_addrinfos(struct ledger_info *ledger,int32_t richlist)
{
    //char coinaddr[256];
    struct ledger_addrinfo *addrinfo;
    uint32_t i,n,addrind; float *sortbuf; uint64_t balance;
    ledger->addrsum = n = 0;
    if ( ledger->addrinfos == 0 )
        return;
    if ( richlist == 0 )
    {
        for (i=1; i<=ledger->addrs.ind; i++)
            if ( (addrinfo= ledger->addrinfos[i]) != 0 && (balance= addrinfo->balance) != 0 )
                ledger->addrsum += balance;
    }
    else
    {
        sortbuf = calloc(ledger->addrs.ind,sizeof(float)+sizeof(uint32_t));
        for (i=1; i<=ledger->addrs.ind; i++)
            if ( (addrinfo= ledger->addrinfos[i]) != 0 && (balance= addrinfo->balance) != 0 )
            {
                ledger->addrsum += balance;
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
                addrinfo = ledger->addrinfos[addrind];
                //memcpy(coinaddr,addrinfo->space,addrinfo->addrlen);
                //coinaddr[addrinfo->addrlen] = 0;
                printf("(%s %.8f) ",addrinfo->coinaddr,sortbuf[i << 1]);
            }
            printf("top.%d of %d\n",i,n);
        }
        free(sortbuf);
    }
}

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
            //else printf("unexpected gap rawind.%d vs hash->ind.%d\n",rawind,hash->ind);
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
    uint32_t rawind = 0;
    *hexlenp = (int32_t)strlen(hexstr) >> 1;
    if ( *hexlenp < 255 )
    {
        decode_hex(data,*hexlenp,hexstr);
        rawind = ledger_rawind(hash,data,*hexlenp);
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
            if ( (ptr= db777_findM(&size,ledger->txids.DB,data,hexlen)) != 0 )
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
        printf("ledger_tx txidind.%d %s vouts.%d vins.%d | ledger->numtxoffsets %d\n",txidind,txidstr,totalvouts,totalspends,ledger->numtxoffsets);
    if ( (checkind= ledger_hexind(&ledger->txids,txid,&txidlen,txidstr)) == txidind )
    {
        memset(&tx,0,sizeof(tx));
        tx.firstvout = totalvouts, tx.firstvin = totalspends, tx.numvouts = numvouts, tx.numvins = numvins;
        tx.txidlen = txidlen, memcpy(tx.txid,txid,txidlen);
        ledger_ensuretxoffsets(ledger,txidind+1);
        ledger_ensurespentbits(ledger,totalvouts + numvouts);
        ledger->txoffsets[txidind].firstvout = totalvouts, ledger->txoffsets[txidind].firstvin = totalspends;
        ledger->txoffsets[txidind+1].firstvout = (totalvouts + numvouts), ledger->txoffsets[txidind+1].firstvin = (totalspends + numvins);
        return(ledger_packtx(ledger->txoffsets_hash,&ledger->txoffsets_state,mem,&tx));
    } else printf("ledger_tx: mismatched txidind, expected %u got %u\n",txidind,checkind); while ( 1 ) sleep(1);
    return(0);
}

uint32_t ledger_addunspent(uint16_t *numaddrsp,uint16_t *numscriptsp,struct ledger_info *ledger,struct alloc_space *mem,uint32_t txidind,uint16_t v,uint32_t unspentind,char *coinaddr,char *scriptstr,uint64_t value)
{
    struct ledger_voutdata vout;
    memset(&vout,0,sizeof(vout));
    memcpy(vout.U.value,&value,sizeof(vout.U.value));
    ledger->voutsum += value;
    //printf("%.8f ",dstr(value));
    if ( (vout.scriptind= ledger_hexind(&ledger->scripts,vout.script,&vout.scriptlen,scriptstr)) == 0 )
    {
        printf("ledger_unspent: error getting scriptind.(%s)\n",scriptstr);
        return(0);
    }
    vout.newscript = (vout.scriptind == ledger->scripts.ind);
    (*numscriptsp) += vout.newscript;
    vout.addrlen = (int32_t)strlen(coinaddr);
    if ( (vout.U.addrind= ledger_rawind(&ledger->addrs,coinaddr,vout.addrlen)) != 0 )
    {
        ledger->unspentmap.ind = ledger->unspentmap.maxind = unspentind;
        if ( db777_add(0,ledger->unspentmap.DB,&unspentind,sizeof(unspentind),&vout.U,sizeof(vout.U)) != 0 )
            printf("error saving unspentmap (%s) %u -> %u %.8f\n",ledger->coinstr,unspentind,vout.U.addrind,dstr(value));
        if ( vout.U.addrind == ledger->addrs.ind )
            vout.newaddr = 1, strcpy(vout.coinaddr,coinaddr), (*numaddrsp)++;
        if ( Debuglevel > 2 )
            printf("txidind.%u v.%d unspent.%d (%s).%u (%s).%u %.8f | %ld\n",txidind,v,unspentind,coinaddr,vout.U.addrind,scriptstr,vout.scriptind,dstr(value),sizeof(vout.U));
        ledger_ensureaddrinfos(ledger,vout.U.addrind);
        ledger->addrinfos[vout.U.addrind] = addrinfo_update(ledger->addrinfos[vout.U.addrind],coinaddr,vout.addrlen,value,unspentind);
         return(ledger_packvout(ledger->addrinfos_hash,&ledger->addrinfos_state,mem,&vout));
    } else printf("ledger_unspent: cant find addrind.(%s)\n",coinaddr);
    return(0);
}

uint32_t ledger_addspend(struct ledger_info *ledger,struct alloc_space *mem,uint32_t spend_txidind,uint32_t totalspends,char *spent_txidstr,uint16_t vout)
{
    struct ledger_spendinfo spend;
    int32_t i,n,size,txidlen,addrind; uint64_t value; uint32_t spent_txidind; uint8_t txid[256];
    struct ledger_addrinfo *addrinfo; struct unspentmap *U;
    //printf("spend_txidind.%d totalspends.%d (%s).v%d\n",spend_txidind,totalspends,spent_txidstr,vout);
    if ( (spent_txidind= ledger_hexind(&ledger->txids,txid,&txidlen,spent_txidstr)) != 0 )
    {
        memset(&spend,0,sizeof(spend));
        spend.spent_txidind = spent_txidind, spend.spent_vout = vout;
        spend.unspentind = ledger->txoffsets[spent_txidind].firstvout + vout;
        SETBIT(ledger->spentbits,spend.unspentind);
        if ( (U= db777_findM(&size,ledger->unspentmap.DB,&spend.unspentind,sizeof(spend.unspentind))) == 0 || size != sizeof(*U) )
        {
            if ( U != 0 )
                free(U);
            for (i=spent_txidind-100; i<=spent_txidind; i++)
                if ( i >= 0 )
                    printf("%d.(%d %d) ",i,ledger->txoffsets[i].firstvout,ledger->txoffsets[i].firstvin);
            printf("error loading unspentmap (%s) unspentind.%u | txidind.%d vout.%d\n",ledger->coinstr,spend.unspentind,spent_txidind,vout);
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
        return(ledger_packspend(ledger->spentbits_hash,&ledger->spentbits_state,mem,&spend));
    } else printf("ledger_spend: cant find txidind for (%s).v%d\n",spent_txidstr,vout);
    return(0);
}

int32_t ledger_compare(struct ledger_info *ledgerA,struct ledger_info *ledgerB)
{
    int32_t i,n;
    if ( ledgerA != 0 && ledgerB != 0 )
    {
        if ( ledgerA->txoffsets == 0 || ledgerB->txoffsets == 0 || (n= ledgerA->numtxoffsets) != ledgerB->numtxoffsets )
            return(-1);
        if ( memcmp(ledgerA->txoffsets,ledgerB->txoffsets,n * sizeof(*ledgerA->txoffsets)) != 0 )
            return(-2);
        if ( ledgerA->spentbits == 0 || ledgerB->spentbits == 0 || (n= ledgerA->numspentbits) != ledgerB->numspentbits )
            return(-3);
        if ( memcmp(ledgerA->spentbits,ledgerB->spentbits,(n >> 3) + 1) != 0 )
            return(-4);
        if ( ledgerA->addrinfos == 0 || ledgerB->addrinfos == 0 || (n= ledgerA->numaddrinfos) != ledgerB->numaddrinfos )
            return(-5);
        for (i=0; i<n; i++)
        {
            if ( (ledgerA->addrinfos[i] != 0) != (ledgerB->addrinfos[i] != 0) )
                return(-6 - i*3);
            if ( ledgerA->addrinfos[i] != 0 && ledgerB->addrinfos[i] != 0 )
            {
                if ( (n= ledgerA->addrinfos[i]->count) != ledgerB->addrinfos[i]->count )
                    return(-6 - i*3 - 1);
                if ( memcmp(ledgerA->addrinfos[i],ledgerB->addrinfos[i],addrinfo_size(n)) != 0 )
                    return(-6 - i*3 - 2);
            }
        }
        return(0);
    }
    return(-1);
}

void ledger_free(struct ledger_info *ledger)
{
    int32_t i;
    if ( ledger != 0 )
    {
        if ( ledger->txoffsets != 0 )
            free(ledger->txoffsets);
        if ( ledger->spentbits != 0 )
            free(ledger->spentbits);
        if ( ledger->addrinfos != 0 )
        {
            for (i=0; i<ledger->numaddrinfos; i++)
                if ( ledger->addrinfos[i] != 0 )
                    free(ledger->addrinfos[i]);
            free(ledger->addrinfos);
        }
        free(ledger);
    }
}

void *ledger_loadptr(int32_t iter,struct alloc_space *mem,long allocsize)
{
    void *src,*ptr;
    src = ptr = memalloc(mem,allocsize,0);
    if ( iter == 1 )
    {
        ptr = calloc(1,allocsize);
        memcpy(ptr,src,allocsize);
    }
    return(ptr);
}

int32_t ledger_saveaddrinfo(FILE *fp,struct ledger_addrinfo *addrinfo)
{
    int32_t allocsize,zero = 0;
    if ( addrinfo == 0 )
        return(fwrite(&zero,1,sizeof(zero),fp) == sizeof(zero));
    else
    {
        allocsize = addrinfo_size(addrinfo->count);
        printf("%d ",allocsize);
        return(fwrite(addrinfo,1,allocsize,fp) == allocsize);
    }
}

int32_t ledger_save(struct ledger_info *ledger,int32_t blocknum)
{
    FILE *fp; long fpos; void *blockledger; int32_t i,err = 0; uint64_t allocsize = 0;
    char ledgername[512];
    if ( ledger->txoffsets == 0 || ledger->spentbits == 0 || ledger->addrinfos == 0 )
    {
        printf("uninitialzed pointer %p %p %p\n",ledger->txoffsets,ledger->spentbits,ledger->addrinfos);
        return(-1);
    }
    sprintf(ledgername,"/tmp/%s.%u",ledger->coinstr,blocknum);
    if ( (fp= fopen(ledgername,"wb")) != 0 )
    {
        if ( fwrite(ledger,1,sizeof(*ledger),fp) != sizeof(*ledger) )
            err++, printf("error saving (%s) L\n",ledgername);
        else if ( fwrite(ledger->txoffsets,ledger->numtxoffsets,sizeof(*ledger->txoffsets),fp) != sizeof(*ledger->txoffsets) )
            err++, printf("error saving (%s) numtxoffsets.%d\n",ledgername,ledger->numtxoffsets);
        else if ( fwrite(ledger->spentbits,1,(ledger->numspentbits>>3)+1,fp) != ((ledger->numspentbits >> 3) + 1) )
            err++, printf("error saving (%s) spentbits.%d\n",ledgername,ledger->numspentbits);
        else
        {
            printf("nutxoffsets.%d numspentbits.%d numaddrinfos.%d before addrinfos %ld\n",ledger->numtxoffsets,ledger->numspentbits,ledger->numaddrinfos,ftell(fp));
            for (i=0; i<ledger->numaddrinfos; i++)
                if ( ledger_saveaddrinfo(fp,ledger->addrinfos[i]) <= 0 )
                {
                    err++, printf("error saving addrinfo.%d (%s)\n",i,ledgername);
                    break;
                }
        }
        fpos = ftell(fp);
        rewind(fp);
        fclose(fp);
        if ( (blockledger= loadfile(&allocsize,ledgername)) != 0 && (allocsize == fpos || allocsize == fpos+1) )
        {
            if ( db777_add(0,ledger->ledger.DB,"ledger",strlen("ledger"),blockledger,(int32_t)fpos) != 0 )
                printf("error saving (%s) %ld\n",ledgername,fpos);
            else printf("saved (%s) %ld %s | crc.%u\n",ledgername,fpos,_mbstr(fpos),_crc32(0,blockledger,fpos));
            free(blockledger);
            return(0);
        } else printf("error loading (%s) allocsize.%llu vs %ld\n",ledgername,(long long)allocsize,fpos);
    }
    return(-1);
}

struct ledger_info *ledger_latest(struct db777 *ledgerDB)
{
    int32_t i,iter,allocsize,len; void *blockledger;
    struct alloc_space MEM;
    struct ledger_addrinfo *addrinfo;
    struct ledger_info *ledger = 0;
    if ( (blockledger= db777_findM(&len,ledgerDB,"ledger",strlen("ledger"))) != 0 )//&& len == sizeof(blocknum) )
    {
        memset(&MEM,0,sizeof(MEM)), MEM.ptr = blockledger, MEM.size = len;
        for (iter=0; iter<2; iter++)
        {
            MEM.used = 0;
            ledger = ledger_loadptr(iter,&MEM,sizeof(*ledger));
            printf("ledger->numtxoffsets.%d ledger->numspentbits.%d ledger->numaddrinfos.%d len.%d crc.%u\n",ledger->numtxoffsets,ledger->numspentbits,ledger->numaddrinfos,len,_crc32(0,blockledger,len));
            ledger->txoffsets = ledger_loadptr(iter,&MEM,ledger->numtxoffsets * 2 * sizeof(*ledger->txoffsets));
            ledger->spentbits = ledger_loadptr(iter,&MEM,(ledger->numspentbits >> 3) + 1);
            printf("before %ld\n",MEM.used);
            if ( iter == 1 )
                ledger->addrinfos = calloc(1,ledger->numaddrinfos * sizeof(*ledger->addrinfos));
            for (i=0; i<ledger->numaddrinfos; i++)
            {
                addrinfo = memalloc(&MEM,sizeof(uint32_t),0);
                if ( addrinfo->count != 0 )
                {
                    printf("%d ",addrinfo->count);
                    allocsize = addrinfo_size(addrinfo->count), memalloc(&MEM,allocsize - sizeof(uint32_t),0);
                    if ( iter == 1 )
                        ledger->addrinfos[i] = calloc(1,allocsize), memcpy(ledger->addrinfos[i],addrinfo,allocsize);
                } ledger->addrinfos[i] = 0;
            }
            if ( iter == 0 && MEM.used != len )
            {
                printf("MEM.used %ld != len.%d\n",MEM.used,len);
                break;
            }
        }
        free(blockledger);
    } else printf("error loading latest (%s)\n",ledger->coinstr);
    return(ledger);
}

int32_t ledger_backup(struct ledger_info *ledger,uint32_t forblocknum)
{
    struct ledger_info *backup; int32_t retval = -100;
    if ( (backup= ledger_latest(ledger->ledger.DB)) != 0 )
    {
        backup->ledger.DB = ledger->ledger.DB, backup->addrs.DB = ledger->addrs.DB, backup->txids.DB = ledger->txids.DB;
        backup->scripts.DB = ledger->scripts.DB, backup->blocks.DB = ledger->blocks.DB, backup->unspentmap.DB = ledger->unspentmap.DB;
        if ( (retval= ledger_compare(ledger,backup)) < 0 )
            printf("ledger miscompared.%d backup %s %d\n",retval,backup->coinstr,backup->blocknum);
        else printf("ledger compared!\n");
        ledger_free(backup);
    }
    ledger->needbackup = 0;
    return(retval);
}

int32_t ledger_commitblock(struct ledger_info *ledger,struct alloc_space *mem,struct ledger_blockinfo *block,int32_t sync)
{
    if ( ledger->blockpending == 0 || ledger->blocknum != block->blocknum )
    {
        printf("ledger_commitblock: mismatched parameter pending.%d (%d %d)\n",ledger->blockpending,ledger->blocknum,block->blocknum);
        return(-1);
    }
    block->allocsize = (uint32_t)mem->used;
    block->crc16 = block_crc16(block);
    if ( Debuglevel > 2 )
        printf("block.%u mem.%p size.%d crc.%u\n",block->blocknum,mem,block->allocsize,block->crc16);
    if ( db777_add(0,ledger->blocks.DB,&block->blocknum,sizeof(block->blocknum),block,block->allocsize) != 0 )
    {
        printf("error saving blocks %s %u\n",ledger->coinstr,block->blocknum);
        return(-1);
    }
    if ( sync != 0 )
        ledger_backup(ledger,block->blocknum);
    ledger->numptrs = ledger->blockpending = 0;
    return(block->allocsize);
}

struct ledger_blockinfo *ledger_startblock(struct ledger_info *ledger,struct alloc_space *mem,uint32_t blocknum,uint64_t minted,int32_t numtx)
{
    struct ledger_blockinfo *block;
    if ( ledger->blockpending != 0 )
    {
        printf("ledger_startblock: cant startblock when %s %u is pending\n",ledger->coinstr,ledger->blocknum);
        return(0);
    }
    ledger->blockpending = 1, ledger->blocknum = blocknum;
    block = memalloc(mem,sizeof(*block),1);
    block->blocknum = blocknum, block->minted = minted, block->numtx = numtx;
    block->txidind = ledger->txids.ind + 1, block->addrind = ledger->addrs.ind + 1, block->scriptind = ledger->scripts.ind + 1;
    block->unspentind = ledger->totalvouts + 1, block->totalspends = ledger->totalspends + 1;
    return(block);
}

struct ledger_blockinfo *ramchain_ledgerupdate(int32_t dispflag,struct ledger_info *ledger,struct alloc_space *mem,struct coin777 *coin,struct rawblock *emit,uint32_t blocknum)
{
    struct rawtx *tx; struct rawvin *vi; struct rawvout *vo; struct ledger_blockinfo *block = 0; int32_t allocsize = 0;
    uint32_t i,txidind,txind,n;
    //printf("ledgerupdate block.%u txidind.%u/%u addrind.%u/%u scriptind.%u/%u unspentind.%u/%u\n",blocknum,lp->txidind,ledger->txids.ind,lp->addrind,ledger->addrs.ind,lp->scriptind,ledger->scripts.ind,lp->totalvouts,ledger->unspentmap.ind);
    if ( rawblock_load(emit,coin->name,coin->serverport,coin->userpass,blocknum) > 0 )
    {
        tx = emit->txspace, vi = emit->vinspace, vo = emit->voutspace;
        block = ledger_startblock(ledger,mem,blocknum,emit->minted,emit->numtx);
        if ( block->numtx > 0 )
        {
            for (txind=0; txind<block->numtx; txind++,tx++)
            {
                if ( (txidind= has_duplicate_txid(ledger,ledger->coinstr,blocknum,tx->txidstr)) == 0 )
                    txidind = ++ledger->txidind;
                //printf("expect txidind.%d unspentind.%d totalspends.%d\n",txidind,block->unspentind+1,block->totalspends);
                ledger_addtx(ledger,mem,txidind,tx->txidstr,ledger->totalvouts+1,tx->numvouts,ledger->totalspends+1,tx->numvins);
                if ( (n= tx->numvouts) > 0 )
                    for (i=0; i<n; i++,vo++,block->numvouts++)
                        ledger_addunspent(&block->numaddrs,&block->numscripts,ledger,mem,txidind,i,++ledger->totalvouts,vo->coinaddr,vo->script,vo->value);
                if ( (n= tx->numvins) > 0 )
                    for (i=0; i<n; i++,vi++,block->numvins++)
                        ledger_addspend(ledger,mem,txidind,++ledger->totalspends,vi->txidstr,vi->vout);
            }
        }
        ledger_recalc_addrinfos(ledger,dispflag);
        if ( (allocsize= ledger_commitblock(ledger,mem,block,ledger->needbackup != 0)) < 0 )
        {
            printf("error updating %s block.%u\n",coin->name,blocknum);
            return(0);
        }
    } else printf("error loading %s block.%u\n",coin->name,blocknum);
    return(block);
}

int32_t ramchain_processblock(struct coin777 *coin,uint32_t blocknum,uint32_t RTblocknum)
{
    struct ramchain *ram = &coin->ramchain;
    struct alloc_space MEM;
    struct ledger_blockinfo *block;
    double estimate,elapsed; int32_t dispflag;
    uint64_t supply,oldsupply = ram->L.voutsum - ram->L.spendsum;
    if ( (ram->RTblocknum % 1000) == 0 || (ram->RTblocknum - blocknum) < 1000 )
        ram->RTblocknum = _get_RTheight(&ram->lastgetinfo,coin->name,coin->serverport,coin->userpass,ram->RTblocknum);
    dispflag = 1 || (blocknum % 100) == 0 || (blocknum > ram->RTblocknum - 1000);
    memset(&MEM,0,sizeof(MEM)), MEM.ptr = &ram->DECODE, MEM.size = sizeof(ram->DECODE);
    block = ramchain_ledgerupdate(dispflag,&ram->L,&MEM,coin,&ram->EMIT,blocknum);
    ram->totalsize += block->allocsize;
    estimate = estimate_completion(ram->startmilli,blocknum-ram->startblocknum,RTblocknum-blocknum)/60000;
    elapsed = (milliseconds()-ram->startmilli)/60000.;
    supply = ram->L.voutsum - ram->L.spendsum;
    if ( dispflag != 0 )
        printf("%-5s [lag %-5d] %-6u supply %.8f %.8f (%.8f) [%.8f] %.8f | dur %.2f %.2f %.2f | len.%-5d %s %.1f ave\n",coin->name,RTblocknum-blocknum,blocknum,dstr(supply),dstr(ram->L.addrsum),dstr(supply)-dstr(ram->L.addrsum),dstr(supply)-dstr(oldsupply),dstr(ram->EMIT.minted),elapsed,estimate,elapsed+estimate,block->allocsize,_mbstr(ram->totalsize),(double)ram->totalsize/blocknum);
    return(0);
    /*rawblock_patch(&ram->EMIT), rawblock_patch(&ram->DECODE);
    ram->DECODE.minted = ram->EMIT.minted = 0;
    if ( (len= memcmp(&ram->EMIT,&ram->DECODE,sizeof(ram->EMIT))) != 0 )
    {
        int i,n = 0;
        for (i=0; i<sizeof(ram->DECODE); i++)
            if ( ((char *)&ram->EMIT)[i] != ((char *)&ram->DECODE)[i] )
                printf("(%02x v %02x).%d ",((uint8_t *)&ram->EMIT)[i],((uint8_t *)&ram->DECODE)[i],i),n++;
        printf("COMPARE ERROR at %d | numdiffs.%d size.%ld\n",len,n,sizeof(ram->DECODE));
    }
    return(0);*/
}

void ramchain_update(struct coin777 *coin)
{
    uint32_t blocknum;
    //printf("%s ramchain_update: ready.%d\n",coin->name,coin->ramchain.readyflag);
    if ( coin->ramchain.readyflag == 0 )
        return;
    if ( (blocknum= coin->ramchain.L.blocknum) < coin->ramchain.RTblocknum )
    {
        if ( blocknum == 0 )
            coin->ramchain.L.blocknum = blocknum = 1;
        if ( ramchain_processblock(coin,blocknum,coin->ramchain.RTblocknum) == 0 )
            coin->ramchain.L.blocknum++;
        else printf("%s error processing block.%d\n",coin->name,blocknum);
    }
}

uint32_t init_hashDBs(struct ramchain *ram,char *coinstr,struct ramchain_hashtable *hash,char *name,char *compression)
{
    uint8_t tmp[256 >> 3];
    if ( hash->DB == 0 )
    {
        hash->DB = db777_create("ramchains",coinstr,name,compression);
        hash->type = name[0];
        strcpy(hash->name,name);
        printf("need to make ramchain_inithash\n");
        //hash->minblocknum = ramchain_inithash(hash);
        ram->DBs[ram->numDBs++] = hash;
        update_sha256(tmp,&hash->state,0,0);
    }
    return(0);
}

uint32_t ensure_ramchain_DBs(struct ramchain *ram,int32_t firstblock)
{
    /* uint32_t i,j,numpurged,minblocknum,nonz,numerrs;
     struct unspent_entry *unspents;
     uint64_t sum,total;
     int64_t errtotal,balance;*/
    ram->L.blocknum = firstblock;
    strcpy(ram->L.coinstr,ram->name);
    init_hashDBs(ram,ram->name,&ram->L.ledger,"ledger","lz4");
    init_hashDBs(ram,ram->name,&ram->L.unspentmap,"unspentmap","lz4");
    init_hashDBs(ram,ram->name,&ram->L.blocks,"blocks","lz4");
    init_hashDBs(ram,ram->name,&ram->L.addrs,"addresses","lz4");
    init_hashDBs(ram,ram->name,&ram->L.txids,"txids",0);
    init_hashDBs(ram,ram->name,&ram->L.scripts,"scripts","lz4");
    /*minblocknum = 0xffffffff;
     for (i=0; i<ram->L.numDBs; i++)
     {
     if ( ram->L.DBs[i]->minblocknum < minblocknum )
     minblocknum = ram-ledger.DBs[i]->minblocknum;
     printf("%u ",ram->L.DBs[i]->minblocknum);
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
    return(firstblock);
}

int32_t init_ramchain(struct coin777 *coin,char *coinstr)
{
    struct ramchain *ram = &coin->ramchain;
    ram->startmilli = milliseconds();
    strcpy(ram->name,coinstr);
    ram->L.blocknum = ram->startblocknum = ensure_ramchain_DBs(ram,1);
    ram->RTblocknum = _get_RTheight(&ram->lastgetinfo,coinstr,coin->serverport,coin->userpass,ram->RTblocknum);
    coin->ramchain.readyflag = 1;
    return(0);
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

int32_t PLUGNAME(_process_json)(struct plugin_info *plugin,uint64_t tag,char *retbuf,int32_t maxlen,char *jsonstr,cJSON *json,int32_t initflag)
{
    char *coinstr,*resultstr,*methodstr;
    struct coin777 *coin;
    int32_t i;
    retbuf[0] = 0;
    printf("<<<<<<<<<<<< INSIDE PLUGIN! process %s\n",plugin->name);
    if ( initflag > 0 )
    {
        if ( DB_NXTaccts == 0 )
            DB_NXTaccts = db777_create(0,0,"NXTaccts",0);
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
                        coin->ramchain.L.needbackup = 1;
                        strcpy(retbuf,"{\"result\":\"queued backup\"}");
                    } else strcpy(retbuf,"{\"error\":\"cant coin not ready\"}");
                }
                else strcpy(retbuf,"{\"error\":\"cant find coin\"}");
            }
            else if ( strcmp(methodstr,"create") == 0 )
            {
                if ( RAMCHAINS.num >= MAX_RAMCHAINS )
                    strcpy(retbuf,"{\"error\":\"cant create any more ramchains\"}");
                else
                {
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
                                int32_t init_ramchain(struct coin777 *coin,char *coinstr);
                                init_ramchain(coin,coinstr);
                                strcpy(RAMCHAINS.coins[RAMCHAINS.num++],coinstr);
                                strcpy(retbuf,"{\"result\":\"ramchain started\"}");
                            } else strcpy(retbuf,"{\"result\":\"ramchain already there\"}");
                        }
                    } else strcpy(retbuf,"{\"result\":\"ramchain already exists\"}");
                }
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
