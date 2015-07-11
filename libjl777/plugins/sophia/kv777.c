//
//  storage.c
//  crypto777
//
//  Created by James on 4/9/15.
//  Copyright (c) 2015 jl777. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>

#ifdef DEFINES_ONLY
#ifndef crypto777_storage_h
#define crypto777_storage_h
#include "mutex.h"
#include "uthash.h"
#include "system777.c"
#define portable_mutex_t struct nn_mutex
#define portable_mutex_init nn_mutex_init
#define portable_mutex_lock nn_mutex_lock
#define portable_mutex_unlock nn_mutex_unlock

#define KV777_ALIGNBITS 2
#define KV777_MAXKEYSIZE 65536
#define KV777_MAXVALUESIZE (1 << 30)

struct kv777_hdditem { uint32_t crc,valuesize,keysize; uint8_t value[]; };
struct kv777_item { UT_hash_handle hh; struct kv777_item *next,*prev; long offset; uint32_t ind,itemsize; struct kv777_hdditem *item; };
struct kv777
{
    char name[64],fname[512];
    struct kv777_item *table,*list;
    portable_mutex_t mutex;
    long totalkeys,totalvalues;
    FILE *fp; void *fileptr; uint64_t mapsize,offset;
    int32_t rwflag,hddflag,multithreaded,numkeys,mmapflag,netkeys,netvalues;
};
int32_t kv777_idle();
void kv777_flush();
struct kv777_item *kv777_write(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t valuesize);
void *kv777_read(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t *valuesizep);
struct kv777 *kv777_init(char *name,int32_t hddflag,int32_t multithreaded,int32_t mmapflag); // kv777_init is NOT THREADSAFE!
int32_t kv777_addstr(struct kv777 *kv,char *key,char *value);
char *kv777_findstr(char *retbuf,int32_t max,struct kv777 *kv,char *key);
int32_t kv777_delete(struct kv777 *kv,void *key,int32_t keysize);

struct KV_node { struct endpoint endpoint; uint64_t nxt64bits,stake; int64_t penalty; uint32_t activetime,nodei; int32_t sock; };
struct KV_item { void *key,*value; int32_t keysize,valuesize; };

struct KV_branch
{
    struct KV_item item;
    int32_t numnodes;
    uint64_t weight;
    struct KV_node nodes[];
};

#define KV777_MAXPEERS 16
#define KV777_FIFODEPTH 16
#define KV777_NUMGENERATORS 16
#define KV777_ORDERED 1
struct kv777_dcntrl
{
    struct kv777 *nodes,**kvs;
    struct KV_node peers[KV777_MAXPEERS];
    uint64_t generators[KV777_FIFODEPTH][KV777_NUMGENERATORS];
    struct endpoint *connections;
    int32_t pubsock,subsock,num,max,numkvs; uint32_t totalnodes,ind,keysize,flags; uint16_t port;
};

struct kv777_dcntrl *KV777_init(char *name,struct kv777 **kvs,int32_t numkvs,uint32_t flags,int32_t pubsock,int32_t subsock,struct endpoint *connections,int32_t num,int32_t max,uint16_t port);
int32_t KV777_addnode(struct kv777_dcntrl *KV,struct endpoint *ep);
int32_t KV777_removenode(struct kv777_dcntrl *KV,struct endpoint *ep);
int32_t KV777_blacklist(struct kv777_dcntrl *KV,struct endpoint *ep,int32_t penalty);
int32_t KV777_submit(struct kv777_dcntrl *KV,void *key,int32_t keysize,void *value,int32_t valuesize);
int32_t KV777_get(struct kv777_dcntrl *KV,struct KV_item *item);
int32_t KV777_put(struct kv777_dcntrl *KV,struct KV_item *item);
int32_t KV777_ping(struct kv777_dcntrl *KV);

#endif
#else
#ifndef crypto777_storage_c
#define crypto777_storage_c

uint32_t _crc32(uint32_t crc,const void *buf,size_t size);

#ifndef crypto777_storage_h
#define DEFINES_ONLY
#include "kv777.c"
#undef DEFINES_ONLY
#endif

struct kv777 **KVS; int32_t Num_kvs; double Last_kvupdate;

void kv777_lock(struct kv777 *kv)
{
    if ( kv->multithreaded != 0 )
        portable_mutex_lock(&kv->mutex);
}

void kv777_unlock(struct kv777 *kv)
{
    if ( kv->multithreaded != 0 )
        portable_mutex_unlock(&kv->mutex);
}

int32_t kv777_isdeleted(struct kv777_hdditem *item) { return(((item)->valuesize & (1 << 31)) != 0); }
void kv777_setdeleted(struct kv777_hdditem *item) { (item)->valuesize |= (1 << 31); }
uint32_t kv777_valuesize(uint32_t valuesize) { return((valuesize) & ~(1 << 31)); }

uint32_t kv777_itemsize(uint32_t keysize,uint32_t valuesize)
{
    int32_t alignmask,alignsize; uint32_t size;
    valuesize = kv777_valuesize(valuesize);
    size = (uint32_t)(sizeof(struct kv777_hdditem) + valuesize + keysize);
    alignsize = (1 << KV777_ALIGNBITS), alignmask = (alignsize - 1);
    if ( KV777_ALIGNBITS > 0 && (valuesize & alignmask) != 0 )
        size += alignsize - (valuesize & alignmask);
    if ( KV777_ALIGNBITS > 0 && (keysize & alignmask) != 0 )
        size += alignsize - (keysize & alignmask);
    return(size);
}

void *kv777_itemkey(struct kv777_hdditem *item)
{
    int32_t alignmask,alignsize,size = item->valuesize;
    alignsize = (1 << KV777_ALIGNBITS), alignmask = (alignsize - 1);
    if ( KV777_ALIGNBITS > 0 && (size & alignmask) != 0 )
        size += alignsize - (size & alignmask);
    return(&item->value[size]);
}

struct kv777_hdditem *kv777_hdditem(uint32_t *allocsizep,void *buf,int32_t maxsize,void *key,int32_t keysize,void *value,int32_t valuesize)
{
    struct kv777_hdditem *item; uint32_t size;
    *allocsizep = size = kv777_itemsize(keysize,valuesize);
    if ( size > maxsize || buf == 0 )
        item = calloc(1,size);
    else item = (struct kv777_hdditem *)buf;
    item->valuesize = valuesize, item->keysize = keysize;
    memcpy(item->value,value,valuesize);
    memcpy(kv777_itemkey(item),key,keysize);
    item->crc = _crc32(0,(void *)((long)item + sizeof(item->crc)),size - sizeof(item->crc));
    //for (int i=0; i<size; i++)
    //    printf("%02x ",((uint8_t *)item)[i]);
    //printf("-> itemsize.%d | %p value.%p %d key.%p %d (%s %s)\n",size,item,item->value,item->valuesize,kv777_itemkey(item),item->keysize,item->value,kv777_itemkey(item));
    return(item);
}

struct kv777_hdditem *kv777_load(uint32_t *allocflagp,uint32_t *itemsizep,struct kv777 *kv)
{
    uint32_t crc,valuesize,keysize,size; long fpos; struct kv777_hdditem *item = 0;
    if ( kv->fileptr != 0 )
    {
        item = (void *)((long)kv->fileptr + kv->offset);
        *itemsizep = size = kv777_itemsize(item->keysize,item->valuesize);
        if ( (kv->offset + size) <= kv->mapsize )
        {
            *allocflagp = 0;
            kv->offset += size;
            return(item);
        }
    }
    fpos = kv->offset;
    fseek(kv->fp,fpos,SEEK_SET);
    *allocflagp = 1;
    if ( fread(&crc,1,sizeof(crc),kv->fp) == sizeof(crc) && crc != 0 )
    {
        if ( fread(&valuesize,1,sizeof(valuesize),kv->fp) != sizeof(valuesize) )
        {
            printf("valuesize read error after %d items\n",kv->numkeys);
            return(0);
        }
        if ( fread(&keysize,1,sizeof(keysize),kv->fp) != sizeof(keysize) || keysize > KV777_MAXKEYSIZE || valuesize > KV777_MAXVALUESIZE )
        {
            printf("keysize read error after %d items keysize.%u valuesize.%u\n",kv->numkeys,keysize,valuesize);
            return(0);
        }
        *itemsizep = size = kv777_itemsize(keysize,valuesize);
        item = calloc(1,size);
        item->valuesize = valuesize, item->keysize = keysize;
        if ( fread(item->value,1,size - sizeof(*item),kv->fp) != (size - sizeof(*item)) )
        {
            printf("valuesize.%d read error after %d items\n",valuesize,kv->numkeys);
            return(0);
        }
        item->crc = _crc32(0,(void *)((long)item + sizeof(item->crc)),size - sizeof(item->crc));
        if ( crc != item->crc )
        {
            uint32_t i;
            for (i=0; i<size; i++)
                printf("%02x ",((uint8_t *)item)[i]);
            printf("kv777.%s error item.%d crc.%x vs calccrc.%x valuesize.%u\n",kv->name,kv->numkeys,crc,item->crc,valuesize);
            return(0);
        }
    } else item = 0;
    kv->offset = ftell(kv->fp);
    return(item);
}

void kv777_free(struct kv777 *kv,struct kv777_item *ptr,int32_t freeall)
{
    if ( kv->fileptr == 0 || (long)ptr->item < (long)kv->fileptr || (long)ptr->item >= (long)kv->fileptr+kv->mapsize )
        free(ptr->item);
    if ( freeall != 0 )
        free(ptr);
}

int32_t kv777_update(struct kv777 *kv,struct kv777_item *ptr)
{
    struct kv777_hdditem *item; uint32_t valuesize; long savepos; int32_t retval = -1;
    if ( kv->fp == 0 )
        return(-1);
    item = (void *)ptr->item;
    savepos = ftell(kv->fp);
    if ( kv777_isdeleted(item) != 0 )
    {
        fseek(kv->fp,ptr->offset + sizeof(item->crc),SEEK_SET);
        if ( fread(&valuesize,1,sizeof(valuesize),kv->fp) == sizeof(valuesize) )
        {
            kv777_setdeleted(item);
            fseek(kv->fp,ptr->offset + sizeof(item->crc),SEEK_SET);
            if ( fwrite(&item->valuesize,1,sizeof(item->valuesize),kv->fp) == sizeof(valuesize) )
                retval = 0;
        } else printf("kv777.%s read error at %ld\n",kv->name,savepos);
        if ( retval != 0 )
            printf("error reading valuesize at fpos.%ld\n",ftell(kv->fp));
        fseek(kv->fp,savepos,SEEK_SET);
        kv777_free(kv,ptr,1);
        return(retval);
    }
    else if ( ptr->offset < 0 )
        ptr->offset = ftell(kv->fp);
    else
    {
        fseek(kv->fp,ptr->offset,SEEK_SET);
        if ( ftell(kv->fp) != ptr->offset )
        {
            printf("kv777 seek warning %ld != %ld\n",ftell(kv->fp),ptr->offset);
            fseek(kv->fp,savepos,SEEK_SET);
            ptr->offset = savepos;
            if ( ftell(kv->fp) != savepos )
            {
                printf("kv777.%s seek error %ld != savepos.%ld\n",kv->name,ftell(kv->fp),savepos);
                exit(-1);
            }
        }
        if ( Debuglevel > 3 )
            printf("updated item.%d at %ld siz.%d\n",ptr->ind,ptr->offset,ptr->itemsize);
        if ( fwrite(ptr->item,1,ptr->itemsize,kv->fp) != ptr->itemsize )
        {
            printf("fwrite.%s error at fpos.%ld\n",kv->name,ftell(kv->fp));
            exit(-1);
        }
        fseek(kv->fp,savepos,SEEK_SET);
        return(0);
    }
    //for (int i=0; i<ptr->itemsize; i++)
    //    printf("%02x ",((uint8_t *)item)[i]);
    //printf("-> itemsize.%d | %p value.%p %d key.%p %d (%s %s)\n",ptr->itemsize,item,item->value,item->valuesize,kv777_itemkey(item),item->keysize,item->value,kv777_itemkey(item));
    if ( fwrite(ptr->item,1,ptr->itemsize,kv->fp) != ptr->itemsize )
    {
        printf("fwrite.%s error at fpos.%ld\n",kv->name,ftell(kv->fp));
        exit(-1);
    }
    else retval = 0;
    return(retval);
}

int32_t kv777_idle()
{
    double gap; struct kv777_item *ptr; struct kv777 *kv; int32_t i,n = 0;
    gap = (milliseconds() - Last_kvupdate);
    if ( Num_kvs > 0 && (gap < 100 || gap > 1000) )
    {
        for (i=0; i<Num_kvs; i++)
        {
            kv = KVS[i];
            kv777_lock(kv);
            if ( (ptr= kv->list) != 0 )
                DL_DELETE(kv->list,ptr);
            kv777_unlock(kv);
            if ( ptr != 0 )
            {
                kv777_update(kv,ptr);
                n++;
                Last_kvupdate = milliseconds();
            }
        }
    }
    return(n);
}

void kv777_flush()
{
    int32_t i; struct kv777 *kv;
    if ( Num_kvs > 0 )
    {
        while ( kv777_idle() > 0 )
            ;
        for (i=0; i<Num_kvs; i++)
        {
            kv = KVS[i];
            if ( kv->fp != 0 )
                fflush(kv->fp);
#ifndef _WIN32
            if ( kv->fileptr != 0 && kv->mapsize != 0 )
                msync(kv->fileptr,kv->mapsize,MS_SYNC);
#endif
        }
    }
}

void kv777_counters(struct kv777 *kv,int32_t polarity,uint32_t keysize,uint32_t valuesize,struct kv777_item *ptr)
{
    kv->totalvalues += polarity * kv777_valuesize(valuesize), kv->netvalues += polarity;
    kv->totalkeys += polarity *  keysize, kv->netkeys += polarity;
    if ( ptr != 0 && kv->hddflag != 0 && kv->rwflag != 0 )
    {
        //kv777_update(kv,ptr);
        DL_APPEND(kv->list,ptr);
    }
}

void kv777_add(struct kv777 *kv,struct kv777_item *ptr,int32_t updatehdd)
{
    kv->numkeys++;
    HASH_ADD_KEYPTR(hh,kv->table,kv777_itemkey(ptr->item),ptr->item->keysize,ptr);
    kv777_counters(kv,1,ptr->item->keysize,ptr->item->valuesize,updatehdd != 0 ? ptr : 0);
}

int32_t kv777_delete(struct kv777 *kv,void *key,int32_t keysize)
{
    void *itemkey; int32_t retval = -1; struct kv777_item *ptr = 0;
    kv777_lock(kv);
    HASH_FIND(hh,kv->table,key,keysize,ptr);
    if ( ptr != 0 )
    {
        itemkey = kv777_itemkey(ptr->item);
        fprintf(stderr,"%d kv777_delete.%p val.%s %s vs %s val.%s\n",kv->netkeys,ptr,ptr->item->value,itemkey,key,ptr->item->value);
        HASH_DELETE(hh,kv->table,ptr);
        kv777_setdeleted(ptr->item);
        kv777_counters(kv,-1,ptr->item->keysize,ptr->item->valuesize,ptr);
        retval = 0;
    }
    kv777_lock(kv);
    return(retval);
}

struct kv777_item *kv777_write(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t valuesize)
{
    struct kv777_item *ptr = 0;
    //if ( kv == SUPERNET.PM )
    //fprintf(stderr,"kv777_write kv.%p table.%p write key.%s size.%d, value.(%s) size.%d\n",kv,kv->table,key,keysize,value,valuesize);
    kv777_lock(kv);
    HASH_FIND(hh,kv->table,key,keysize,ptr);
    if ( ptr != 0 )
    {
        if ( ptr->item != 0 )
        {
            if ( valuesize == ptr->item->valuesize && memcmp(ptr->item->value,value,valuesize) == 0 )
            {
                if ( Debuglevel > 3 )
                    fprintf(stderr,"%d IDENTICAL.%p val.%s %s vs %s val.%s\n",kv->netkeys,ptr,ptr->item->value,kv777_itemkey(ptr->item),key,value);
                kv777_unlock(kv);
                return(ptr);
            }
            else if ( Debuglevel > 3 )
                printf("kv777_write (%s) != (%s)\n",ptr->item->value,value);
            kv777_counters(kv,-1,ptr->item->keysize,ptr->item->valuesize,0);
            kv777_free(kv,ptr,0);
        } else printf("kv777_write: null item?\n");
        if ( Debuglevel > 3 )
            fprintf(stderr,"%d REPLACE.%p val.%s %s vs %s val.%s\n",kv->netkeys,ptr,ptr->item->value,kv777_itemkey(ptr->item),key,value);
        if ( kv777_itemsize(keysize,valuesize) > ptr->itemsize )
            ptr->offset = -1;
        if ( (ptr->item= kv777_hdditem(&ptr->itemsize,0,0,key,keysize,value,valuesize)) != 0 )
            kv777_counters(kv,1,keysize,valuesize,ptr);
        else if ( Debuglevel > 3 )
            printf("kv777_write: couldnt create item.(%s) %s ind.%d offset.%ld\n",key,value,kv->numkeys,ftell(kv->fp));
    }
    else
    {
        ptr = calloc(1,sizeof(struct kv777_item));
        ptr->ind = kv->numkeys, ptr->offset = -1;
        if ( (ptr->item= kv777_hdditem(&ptr->itemsize,0,0,key,keysize,value,valuesize)) == 0 )
        {
            printf("kv777_write: couldnt create item.(%s) %s ind.%d offset.%ld\n",key,value,kv->numkeys,ftell(kv->fp));
            free(ptr), ptr = 0;
        } else  kv777_add(kv,ptr,1);
        if ( Debuglevel > 3 )
            fprintf(stderr,"%d CREATE.%p val.%s %s vs %s val.%s\n",kv->netkeys,ptr,ptr->item->value,kv777_itemkey(ptr->item),key,value);
    }
    kv777_unlock(kv);
    return(ptr);
}

void *kv777_read(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t *valuesizep)
{
    struct kv777_hdditem *item = 0; struct kv777_item *ptr = 0;
    kv777_lock(kv);
    HASH_FIND(hh,kv->table,key,keysize,ptr);
    kv777_unlock(kv);
    if ( ptr != 0 && (item= ptr->item) != 0 && kv777_isdeleted(item) == 0 )
    {
        if ( valuesizep != 0 )
        {
            if ( value != 0 && item->valuesize <= *valuesizep )
                memcpy(value,item->value,item->valuesize);
            *valuesizep = item->valuesize;
        }
        return(item->value);
    }
    if ( Debuglevel > 3 )
        printf("kv777_read ptr.%p item.%p key.%s keysize.%d\n",ptr,item,key,keysize);
    if ( valuesizep != 0 )
        *valuesizep = 0;
    return(0);
}

int32_t kv777_addstr(struct kv777 *kv,char *key,char *value)
{
    struct kv777_item *ptr;
    if ( (ptr= kv777_write(kv,key,(int32_t)strlen(key)+1,value,(int32_t)strlen(value)+1)) != 0 )
        return(ptr->ind);
    return(-1);
}

char *kv777_findstr(char *retbuf,int32_t max,struct kv777 *kv,char *key) { return(kv777_read(kv,key,(int32_t)strlen(key)+1,retbuf,&max)); }

struct kv777 *kv777_init(char *name,int32_t hddflag,int32_t multithreaded,int32_t mmapflag) // kv777_init IS NOT THREADSAFE!
{
    long offset = 0; struct kv777_hdditem *item; uint32_t i,itemsize,allocflag;
    struct kv777_item *ptr; struct kv777 *kv;
//#ifdef _WIN32
    mmapflag = 0;
//#endif
    if ( Num_kvs > 0 )
    {
        for (i=0; i<Num_kvs; i++)
            if ( strcmp(KVS[i]->name,name) == 0 )
                return(KVS[i]);
    }
    kv = calloc(1,sizeof(*kv));
    safecopy(kv->name,name,sizeof(kv->name));
    portable_mutex_init(&kv->mutex);
    kv->rwflag = 1, kv->hddflag = hddflag, kv->mmapflag = mmapflag * SUPERNET.mmapflag;
    if ( SOPHIA.PATH[0] == 0 )
        strcpy(SOPHIA.PATH,"DB");
    sprintf(kv->fname,"%s/%s",SOPHIA.PATH,kv->name), os_compatible_path(kv->fname);
    if ( hddflag != 0 && (kv->fp= fopen(kv->fname,"rb+")) == 0 )
        kv->fp = fopen(kv->fname,"wb+");
    if ( kv->fp != 0 )
    {
        if ( kv->mmapflag != 0 )
        {
            fseek(kv->fp,0,SEEK_END);
            kv->mapsize = ftell(kv->fp);
            kv->fileptr = map_file(kv->fname,&kv->mapsize,1);
        }
        rewind(kv->fp);
        while ( (item= kv777_load(&allocflag,&itemsize,kv)) != 0 )
        {
            //printf("%d: item.%p itemsize.%d\n",kv->numkeys,item,itemsize);
            if ( kv777_isdeleted(item) != 0 && allocflag != 0 )
                free(item);
            else
            {
                ptr = calloc(1,sizeof(*ptr));
                ptr->itemsize = itemsize;
                ptr->item = item;
                ptr->ind = kv->numkeys;
                ptr->offset = offset;
                kv777_add(kv,ptr,0);
                //fprintf(stderr,"[%s] add item.%d crc.%u valuesize.%d keysize.%d [%s]\n",item->value,kv->numkeys,item->crc,item->valuesize,item->keysize,kv777_itemkey(item));
            }
            offset = kv->offset; //ftell(kv->fp);
        }
    }
    printf("kv777.%s fpos.%ld -> goodpos.%ld fileptr.%p mapsize.%ld | numkeys.%d netkeys.%d netvalues.%d\n",kv->name,kv->fp != 0 ? ftell(kv->fp) : 0,offset,kv->fileptr,(long)kv->mapsize,kv->numkeys,kv->netkeys,kv->netvalues);
    if ( kv->fp != 0 && offset != ftell(kv->fp) )
    {
        printf("strange position?, seek\n");
        fseek(kv->fp,offset,SEEK_SET);
    }
    kv->multithreaded = multithreaded;
    KVS = realloc(KVS,sizeof(*KVS) * (Num_kvs + 1));
    KVS[Num_kvs++] = kv;
    return(kv);
}

void kv777_test(int32_t n)
{
    struct kv777 *kv; void *rval; int32_t errors,iter,i=1,j,len,keylen,valuesize; uint8_t key[32],value[32],result[1024]; double startmilli;
    SUPERNET.mmapflag = 1;
    //Debuglevel = 3;
    for (iter=errors=0; iter<3; iter++)
    {
        startmilli = milliseconds();
        if ( (kv= kv777_init("test",1,1,1)) != 0 )
        {
            srand(777);
            for (i=0; i<n; i++)
            {
                //printf("i.%d of n.%d\n",i,n);
                valuesize = (rand() % (sizeof(value)-1)) + 1;
                keylen = (rand() % (sizeof(key)-8)) + 8;
                memset(key,0,sizeof(key));
                for (j=0; j<keylen; j++)
                    key[j] = safechar64(rand());
                sprintf((void *)key,"%d",i);
                keylen = (int32_t)strlen((void *)key);
                for (j=0; j<valuesize; j++)
                    value[j] = safechar64(rand());
                if ( 1 && iter != 0 && (i % 1000) == 0 )
                    value[0] ^= 0xff;
                kv777_write(kv,key,keylen,value,valuesize);
                if ( (rval= kv777_read(kv,key,keylen,result,&len)) != 0 )
                {
                    if ( len != valuesize || memcmp(value,rval,valuesize) != 0 )
                        errors++, printf("len.%d vs valuesize.%d or data mismatch\n",len,valuesize);
                } else errors++, printf("kv777_read error i.%d cant find key added, len.%d, valuesize.%d\n",i,len,valuesize);
            }
        }
        printf("iter.%d fileptr.%p finished kv777_test %d iterations, %.4f millis ave -> %.1f seconds\n",iter,kv->fileptr,i,(milliseconds() - startmilli) / i,.001*(milliseconds() - startmilli));
    }
    kv777_flush();
    printf("errors.%d finished kv777_test %d iterations, %.4f millis ave -> %.1f seconds after flush\n",errors,i,(milliseconds() - startmilli) / i,.001*(milliseconds() - startmilli));
}

int32_t KV777_connect(struct kv777_dcntrl *KV,struct endpoint *ep)
{
    int32_t j; char endpoint[512];
    if ( KV == 0 || KV->subsock < 0 )
        return(-1);
    for (j=0; j<KV->num; j++)
        if ( memcmp(ep,&KV->connections[j],sizeof(*ep)) == 0 )
            return(0);;
    if ( j == KV->num )
    {
        expand_epbits(endpoint,*ep);
        printf("connect to (%s)\n",endpoint);
        if ( nn_connect(KV->subsock,endpoint) < 0 )
            printf("KV777_init warning: error connecting to (%s) %s\n",endpoint,nn_errstr());
        else
        {
            if ( KV->num >= KV->max )
                printf("KV777_init warning: num.%d > max.%d (%s)\n",KV->num,KV->max,endpoint);
            KV->connections[KV->num++ % KV->max] = *ep;
            return(1);
        }
    }
    return(-1);
}

int32_t KV777_addnode(struct kv777_dcntrl *KV,struct endpoint *ep)
{
    struct KV_node node; uint32_t ind = KV->nodes->numkeys;
    printf("addnode %x\n",ep->ipbits);
    memset(&node,0,sizeof(node));
    node.endpoint = *ep;
    if ( kv777_write(KV->nodes,ep,sizeof(*ep),&node,sizeof(node)) == 0 || kv777_write(KV->nodes,&ind,sizeof(ind),ep,sizeof(*ep)) == 0 )
        return(-1);
    return(0);
}

int32_t KV777_ping(struct kv777_dcntrl *KV)
{
    uint32_t i,nonce; int32_t size; struct endpoint endpoint,*ep; char *retstr,*jsonstr,buf[512]; cJSON *array,*json;
    json = cJSON_CreateObject();
    cJSON_AddItemToObject(json,"agent",cJSON_CreateString("kv777"));
    cJSON_AddItemToObject(json,"method",cJSON_CreateString("ping"));
    cJSON_AddItemToObject(json,"unixtime",cJSON_CreateNumber(time(NULL)));
    cJSON_AddItemToObject(json,"myendpoint",cJSON_CreateString(SUPERNET.relayendpoint));
    array = cJSON_CreateArray();
    cJSON_AddItemToArray(array,cJSON_CreateString(SUPERNET.relayendpoint));
    for (i=0; i<KV->nodes->numkeys; i++)
    {
        size = sizeof(endpoint);
        if ( (ep= kv777_read(KV->nodes,&i,sizeof(i),&endpoint,&size)) != 0 && size == sizeof(endpoint) )
        {
            expand_epbits(buf,*ep);
            cJSON_AddItemToArray(array,cJSON_CreateString(buf));
        }
    }
    cJSON_AddItemToObject(json,"peers",array);
    jsonstr = cJSON_Print(json), _stripwhite(jsonstr,' '), free_json(json);
    if ( (retstr= busdata_sync(&nonce,jsonstr,"allrelays",0)) != 0 )
    {
        printf("KV777_ping.(%s)\n",jsonstr);
        free(retstr);
    }
    free(jsonstr);
    return(0);
}

char *KV777_processping(cJSON *json,char *jsonstr)
{
    cJSON *array; int32_t i,j,n,size; struct endpoint endpoint,*ep; char ipaddr[64],buf[512],*endpointstr; uint16_t port;
    if ( SUPERNET.relays == 0 )
        return(clonestr("{\"error\":\"no relays KV777\"}"));
    if ( (array= cJSON_GetObjectItem(json,"peers")) != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            if ( (endpointstr= cJSON_str(cJSON_GetArrayItem(array,i))) != 0 )
            {
                for (j=0; j<SUPERNET.relays->nodes->numkeys; j++)
                {
                    size = sizeof(endpoint);
                    if ( (ep= kv777_read(SUPERNET.relays->nodes,&j,sizeof(j),&endpoint,&size)) != 0 && size == sizeof(endpoint) )
                    {
                        expand_epbits(buf,*ep);
                        if ( strcmp(buf,endpointstr) == 0 )
                            break;
                    }
                }
                if ( j == SUPERNET.relays->nodes->numkeys && strcmp(endpointstr,SUPERNET.relayendpoint) != 0 )
                {
                    port = parse_ipaddr(ipaddr,endpointstr+6);
                    printf("ipaddr.(%s):%d\n",ipaddr,port);
                    endpoint = calc_epbits(SUPERNET.transport,(uint32_t)calc_ipbits(ipaddr),port,NN_PUB);
                    KV777_connect(SUPERNET.relays,&endpoint);
                    KV777_addnode(SUPERNET.relays,&endpoint);
                }
            }
        }
    }
    printf("KV777 GOT.(%s)\n",jsonstr);
    return(clonestr("{\"result\":\"success\"}"));
}

struct kv777_dcntrl *KV777_init(char *name,struct kv777 **kvs,int32_t numkvs,uint32_t flags,int32_t pubsock,int32_t subsock,struct endpoint *connections,int32_t num,int32_t max,uint16_t port)
{
    struct kv777_dcntrl *KV = calloc(1,sizeof(*KV));
    struct endpoint endpoint,*ep; char buf[512]; int32_t i,size,sendtimeout=10,recvtimeout=10;
    KV->port = port; KV->connections = connections, KV->num = num, KV->max = max, KV->flags = flags, KV->kvs = kvs, KV->numkvs = numkvs;
    buf[0] = 0;
    if ( (KV->pubsock= pubsock) < 0 && (KV->pubsock= nn_createsocket(buf,1,"NN_PUB",NN_SUB,port,sendtimeout,recvtimeout)) < 0 )
    {
        printf("KV777_init pubsocket failure %d %s\n",KV->pubsock,buf);
        free(KV);
        return(0);
    }
    buf[0] = 0;
    if ( (KV->subsock= subsock) < 0 && (KV->subsock= nn_createsocket(buf,0,"NN_SUB",NN_SUB,0,sendtimeout,recvtimeout)) >= 0 )
        nn_setsockopt(KV->subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
    if ( KV->subsock < 0 )
    {
        printf("KV777_init subsocket failure %d\n",KV->subsock);
        free(KV);
        return(0);
    }
    sprintf(buf,"%s.nodes",name);
    KV->nodes = kv777_init(buf,1,1,SUPERNET.mmapflag);
    for (i=0; i<KV->nodes->numkeys; i++) // connect all nodes in DB that are not already connected
    {
        size = sizeof(endpoint);
        if ( (ep= kv777_read(KV->nodes,&i,sizeof(i),&endpoint,&size)) != 0 && size == sizeof(endpoint) )
            KV777_connect(KV,ep);
    }
    for (i=0; i<num; i++) // add all nodes not in DB to DB
    {
        expand_epbits(buf,connections[i]);
        if ( kv777_read(KV->nodes,&connections[i],sizeof(connections[i]),0,0) == 0 )
        {
            if ( KV777_addnode(KV,&connections[i]) != 0 )
                printf("KV777_init warning: error adding node to (%s)\n",buf);
        }
    }
    return(KV);
}

#endif
#endif
