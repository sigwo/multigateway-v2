//
//  storage.c
//  crypto777
//
//  Created by James on 4/9/15.
//  Copyright (c) 2015 jl777. All rights reserved.
//

#ifdef DEFINES_ONLY
#ifndef crypto777_storage_h
#define crypto777_storage_h
#include <stdio.h>
#include <stdint.h>
#include "mutex.h"
#include "uthash.h"
#include "bits777.c"
#define portable_mutex_t struct nn_mutex
#define portable_mutex_init nn_mutex_init
#define portable_mutex_lock nn_mutex_lock
#define portable_mutex_unlock nn_mutex_unlock

struct kv777_item { UT_hash_handle hh; struct kv777_item *next,*prev; long offset; uint32_t crc,maxsize,valuesize,ind; uint8_t value[]; };
struct kv777
{
    char name[64],fname[512];
    struct kv777_item *table,*list;
    portable_mutex_t mutex;
    FILE *fp;
    int32_t rwflag,hddflag,multithreaded,numkeys;
};
int32_t kv777_idle();
void kv777_flush();
struct kv777_item *kv777_write(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t valuesize);
void *kv777_read(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t *valuesizep);
struct kv777 *kv777_init(char *name,int32_t hddflag,int32_t multithreaded); // NOT THREADSAFE!

#endif
#else
#ifndef crypto777_storage_c
#define crypto777_storage_c


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

int32_t kv777_update(struct kv777 *kv,struct kv777_item *ptr)
{
    uint8_t buf[65536],*value; uint32_t valuesize; long savepos,size,offset = 0; int32_t retval = -1;
    if ( kv->fp == 0 )
        return(-1);
    size = ptr->valuesize + sizeof(ptr->valuesize) + ptr->hh.keylen + sizeof(ptr->hh.keylen);
    if ( (ptr->valuesize & (1<<31)) != 0 )
    {
        savepos = ftell(kv->fp);
        fseek(kv->fp,ptr->offset + sizeof(ptr->crc),SEEK_SET);
        if ( fread(&valuesize,1,sizeof(valuesize),kv->fp) == sizeof(valuesize) )
        {
            valuesize |= (1 << 31);
            fseek(kv->fp,ptr->offset + sizeof(ptr->crc),SEEK_SET);
            if ( fwrite(&valuesize,1,sizeof(valuesize),kv->fp) == sizeof(valuesize) )
                retval = 0;
        }
        if ( retval != 0 )
            printf("error reading valuesize at fpos.%ld\n",ftell(kv->fp));
        fseek(kv->fp,savepos,SEEK_SET);
        return(retval);
    } else ptr->offset = ftell(kv->fp);
    if ( size > sizeof(buf) )
        value = malloc(size);
    else value = buf;
    memcpy(&value[offset],&ptr->crc,sizeof(ptr->crc)), offset += sizeof(ptr->crc);
    memcpy(&value[offset],&ptr->valuesize,sizeof(ptr->valuesize)), offset += sizeof(ptr->valuesize);
    memcpy(&value[offset],&ptr->hh.keylen,sizeof(ptr->hh.keylen)), offset += sizeof(ptr->hh.keylen);
    memcpy(&value[offset],ptr->value,ptr->valuesize), offset += ptr->valuesize;
    memcpy(&value[offset],ptr->hh.key,ptr->hh.keylen), offset += ptr->hh.keylen;
    if ( fwrite(value,1,offset,kv->fp) != offset )
        printf("fwrite.%s error at fpos.%ld\n",kv->name,ftell(kv->fp));
    else retval = 0;
    if ( value != buf )
        free(value);
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
            if ( kv->rwflag != 0 && kv->fp != 0 )//kv->hddflag != 0 && kv->M.fileptr != 0 )
                fflush(kv->fp);
        }
    }
}

int32_t kv777_delete(struct kv777 *kv,void *key,int32_t keysize)
{
    static uint32_t counter;
    int32_t retval = -1; struct kv777_item *ptr = 0;
    kv777_lock(kv);
    HASH_FIND(hh,kv->table,key,keysize,ptr);
    if ( ptr != 0 )
    {
        fprintf(stderr,"%d kv777_delete.%p val.%x %x vs %x val.%x\n",counter,ptr,*(int *)ptr->value,*(int *)ptr->hh.key,*(int *)key,*(int *)ptr->value);
        HASH_DELETE(hh,kv->table,ptr);
        ptr->valuesize |= (1 << 31);
        if ( kv->hddflag != 0 && kv->rwflag != 0 )
            DL_APPEND(kv->list,ptr);
        else free(ptr);
        counter++;
        retval = 0;
    }
    kv777_lock(kv);
    return(retval);
}

struct kv777_item *kv777_write(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t valuesize)
{
    void *newkey; int32_t ind,duplicate = 0; struct kv777_item *ptr = 0;
    if ( kv == SUPERNET.PM )
        fprintf(stderr,"kv777_write kv.%p table.%p write key.%u size.%d, value.(%s) size.%d\n",kv,kv->table,*(int *)key,keysize,value,valuesize);
    kv777_lock(kv);
    HASH_FIND(hh,kv->table,key,keysize,ptr);
    if ( ptr != 0 )
    {
        static uint32_t counter;
        if ( valuesize == ptr->valuesize && memcmp(ptr->value,value,valuesize) == 0 )
        {
            //fprintf(stderr,"%d IDENTICAL.%p val.%x %x vs %x val.%x\n",counter,ptr,*(int *)ptr->value,*(int *)ptr->hh.key,*(int *)key,*(int *)value);
            kv777_unlock(kv);
            return(ptr);
        }
        ind = ptr->ind;
        fprintf(stderr,"%d DELETE.%p val.%x %x vs %x val.%x\n",counter,ptr,*(int *)ptr->value,*(int *)ptr->hh.key,*(int *)key,*(int *)value);
        HASH_DELETE(hh,kv->table,ptr);
        free(ptr);
        counter++;
        duplicate = 1;
    } else ind = kv->numkeys;
    ptr = calloc(1,sizeof(struct kv777_item) + valuesize);
    ptr->ind = ind;
    //fprintf(stderr,"key.%p %x alloc.%p size.%ld\n",key,*(int *)key,ptr,sizeof(struct kv777_item) + valuesize);
    newkey = malloc(keysize);
    memcpy(newkey,key,keysize);
    if ( duplicate == 0 )
        kv->numkeys++;
    HASH_ADD_KEYPTR(hh,kv->table,newkey,keysize,ptr);
    ptr->valuesize = ptr->maxsize = valuesize;
    memcpy(ptr->value,value,valuesize);
    ptr->crc = _crc32(_crc32(0,value,valuesize),key,keysize);
    if ( 1 && kv->hddflag != 0 && kv->rwflag != 0 )
        DL_APPEND(kv->list,ptr);
    kv777_unlock(kv);
    return(ptr);
}

void *kv777_read(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t *valuesizep)
{
    struct kv777_item *ptr = 0;
    kv777_lock(kv);
    HASH_FIND(hh,kv->table,key,keysize,ptr);
    kv777_unlock(kv);
    if ( ptr != 0 )
    {
        if ( ptr->valuesize <= *valuesizep )
        {
            if ( value != 0 )
                memcpy(value,ptr->value,ptr->valuesize);
        }
        *valuesizep = ptr->valuesize;
        return(ptr->value);
    }
    *valuesizep = 0;
    return(0);
}

struct kv777 *kv777_init(char *name,int32_t hddflag,int32_t multithreaded) // NOT THREADSAFE!
{
    void *key; long offset,goodpos = 0; uint32_t crc,calccrc,keylen,valuesize,deleted,i=0;
    struct kv777_item *ptr; struct kv777 *kv = calloc(1,sizeof(*kv));
    safecopy(kv->name,name,sizeof(kv->name));
    portable_mutex_init(&kv->mutex);
    kv->rwflag = 1, kv->hddflag = hddflag;
    if ( SOPHIA.PATH[0] == 0 )
        strcpy(SOPHIA.PATH,"DB");
    sprintf(kv->fname,"%s/%s",SOPHIA.PATH,kv->name), os_compatible_path(kv->fname);
    if ( (kv->fp= fopen(kv->fname,"rb+")) == 0 )
        kv->fp = fopen(kv->fname,"wb+");
    if ( kv->fp != 0 && kv->rwflag != 0 )
    {
        offset = goodpos;
        while ( fread(&crc,1,sizeof(crc),kv->fp) == sizeof(crc) && crc != 0 )
        {
            if ( fread(&valuesize,1,sizeof(valuesize),kv->fp) != sizeof(valuesize) )
            {
                printf("valuesize read error after %d items\n",i);
                break;
            }
            if ( (valuesize & (1<<31)) != 0 )
                deleted = 1, valuesize &= ~(1<<31);
            else deleted = 0;
            if ( fread(&keylen,1,sizeof(keylen),kv->fp) != sizeof(keylen) )
            {
                printf("keylen read error after %d items\n",i);
                break;
            }
            ptr = calloc(1,sizeof(struct kv777_item) + valuesize);
            if ( fread(&ptr->value,1,valuesize,kv->fp) != valuesize )
            {
                printf("valuesize.%d read error after %d items\n",valuesize,i);
                break;
            }
            key = malloc(keylen);
            if ( fread(key,1,keylen,kv->fp) != keylen )
            {
                printf("key.%d read error after %d items\n",keylen,i);
                break;
            }
            calccrc = _crc32(_crc32(0,ptr->value,valuesize),key,keylen);
            if ( crc != calccrc )
            {
                printf("kv777.%s error item.%d crc.%u vs calccrc.%u valuesize.%u\n",kv->name,i,crc,calccrc,valuesize);
                break;
            }
            if ( deleted == 0 )
            {
                ptr->valuesize = ptr->maxsize = valuesize;
                ptr->crc = calccrc;
                ptr->offset = offset;
                ptr->ind = i;
                if ( strcmp(name,"PM") == 0 )
                    fprintf(stderr,"[%x] %s add item.%d crc.%u valuesize.%d keysize.%d [%d]\n",*(int *)ptr->value,ptr->value,i,calccrc,valuesize,keylen,*(int *)key);
                HASH_ADD_KEYPTR(hh,kv->table,key,keylen,ptr);
                i++;
            }
            else free(ptr), free(key);
            goodpos = ftell(kv->fp);
        }
    }
    kv->numkeys = i;
    printf("kv777.%s added %d items, fpos.%ld -> goodpos.%ld\n",kv->name,i,ftell(kv->fp),goodpos);
    if ( goodpos != ftell(kv->fp) )
        fseek(kv->fp,goodpos,SEEK_SET);
    kv->multithreaded = multithreaded;
    KVS = realloc(KVS,sizeof(*KVS) * (Num_kvs + 1));
    KVS[Num_kvs++] = kv;
    return(kv);
}

void kv777_test()
{
    struct kv777 *kv; void *rval; int32_t i=1,j,len,keylen,valuesize,n = 1000000; uint8_t key[32],value[32]; double startmilli;
    startmilli = milliseconds();
    if ( (kv= kv777_init("test",1,1)) != 0 )
    {
        srand(777);
        for (i=0; i<n; i++)
        {
            //printf("i.%d of n.%d\n",i,n);
            valuesize = (rand() % (sizeof(value)-1)) + 1;
            if ( (valuesize & 3) != 0 )
                valuesize += 4 - (valuesize & 3);
            keylen = (rand() % (sizeof(key)-8)) + 8;
            memset(key,0,sizeof(key));
            for (j=0; j<keylen; j++)
                key[j] = rand();
            for (j=0; j<valuesize; j++)
                value[j] = rand();
            kv777_write(kv,key,keylen,value,valuesize);
            if ( (rval= kv777_read(kv,key,keylen,0,&len)) != 0 )
            {
                if ( len != valuesize || memcmp(value,rval,valuesize) != 0 )
                    printf("len.%d vs valuesize.%d or data mismatch\n",len,valuesize);
            } else printf("kv777_read error i.%d cant find key added, len.%d, valuesize.%d\n",i,len,valuesize);
        }
    }
    printf("finished kv777_test %d iterations, %.3f millis ave -> %.1f seconds\n",i,(milliseconds() - startmilli) / i,.001*(milliseconds() - startmilli));
    kv777_flush();
    printf("finished kv777_test %d iterations, %.3f millis ave -> %.1f seconds\n",i,(milliseconds() - startmilli) / i,.001*(milliseconds() - startmilli));
}

#endif
#endif
