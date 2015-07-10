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
    FILE *fp; void *fileptr; uint64_t mapsize,offset;
    int32_t rwflag,hddflag,multithreaded,numkeys,mmapflag;
};
int32_t kv777_idle();
void kv777_flush();
struct kv777_item *kv777_write(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t valuesize);
void *kv777_read(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t *valuesizep);
struct kv777 *kv777_init(char *name,int32_t hddflag,int32_t multithreaded,int32_t mmapflag); // kv777_init is NOT THREADSAFE!
int32_t kv777_addstr(struct kv777 *kv,char *key,char *value);
char *kv777_findstr(char *retbuf,int32_t max,struct kv777 *kv,char *key);
int32_t kv777_delete(struct kv777 *kv,void *key,int32_t keysize);

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

uint32_t kv777_itemsize(uint32_t valuesize,uint32_t keysize)
{
    int32_t alignmask,alignsize; uint32_t size;
    valuesize &= ~(1<<31);
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
    *allocsizep = size = kv777_itemsize(valuesize,keysize);
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
        *itemsizep = size = kv777_itemsize(item->valuesize,item->keysize);
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
        *itemsizep = size = kv777_itemsize(valuesize,keysize);
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
            for (int i=0; i<size; i++)
                printf("%02x ",((uint8_t *)item)[i]);
            printf("kv777.%s error item.%d crc.%x vs calccrc.%x valuesize.%u\n",kv->name,kv->numkeys,crc,item->crc,valuesize);
            return(0);
        }
    } else item = 0;
    kv->offset = ftell(kv->fp);
    return(item);
}

int32_t kv777_update(struct kv777 *kv,struct kv777_item *ptr)
{
    struct kv777_hdditem *item; uint32_t valuesize; long savepos; int32_t retval = -1;
    if ( kv->fp == 0 )
        return(-1);
    item = (void *)ptr->item;
    if ( (item->valuesize & (1<<31)) != 0 )
    {
        savepos = ftell(kv->fp);
        fseek(kv->fp,ptr->offset + sizeof(item->crc),SEEK_SET);
        if ( fread(&valuesize,1,sizeof(valuesize),kv->fp) == sizeof(valuesize) )
        {
            valuesize |= (1 << 31);
            fseek(kv->fp,ptr->offset + sizeof(item->crc),SEEK_SET);
            if ( fwrite(&valuesize,1,sizeof(valuesize),kv->fp) == sizeof(valuesize) )
                retval = 0;
        }
        if ( retval != 0 )
            printf("error reading valuesize at fpos.%ld\n",ftell(kv->fp));
        fseek(kv->fp,savepos,SEEK_SET);
        return(retval);
    } else ptr->offset = ftell(kv->fp);
    //for (int i=0; i<ptr->itemsize; i++)
    //    printf("%02x ",((uint8_t *)item)[i]);
    //printf("-> itemsize.%d | %p value.%p %d key.%p %d (%s %s)\n",ptr->itemsize,item,item->value,item->valuesize,kv777_itemkey(item),item->keysize,item->value,kv777_itemkey(item));
    if ( fwrite(ptr->item,1,ptr->itemsize,kv->fp) != ptr->itemsize )
        printf("fwrite.%s error at fpos.%ld\n",kv->name,ftell(kv->fp));
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
            if ( kv->fileptr != 0 && kv->mapsize != 0 )
                msync(kv->fileptr,kv->mapsize,MS_SYNC);
        }
    }
}

int32_t kv777_delete(struct kv777 *kv,void *key,int32_t keysize)
{
    static uint32_t counter;
    void *itemkey; int32_t retval = -1; struct kv777_item *ptr = 0;
    kv777_lock(kv);
    HASH_FIND(hh,kv->table,key,keysize,ptr);
    if ( ptr != 0 )
    {
        itemkey = kv777_itemkey(ptr->item);
        fprintf(stderr,"%d kv777_delete.%p val.%s %s vs %s val.%s\n",counter,ptr,ptr->item->value,itemkey,key,ptr->item->value);
        HASH_DELETE(hh,kv->table,ptr);
        ptr->item->valuesize |= (1 << 31);
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
    int32_t ind,duplicate = 0; struct kv777_item *ptr = 0;
    //if ( kv == SUPERNET.PM )
    //fprintf(stderr,"kv777_write kv.%p table.%p write key.%s size.%d, value.(%s) size.%d\n",kv,kv->table,key,keysize,value,valuesize);
    kv777_lock(kv);
    HASH_FIND(hh,kv->table,key,keysize,ptr);
    if ( ptr != 0 )
    {
        static uint32_t counter;
        if ( valuesize == ptr->item->valuesize && memcmp(ptr->item->value,value,valuesize) == 0 )
        {
            //fprintf(stderr,"%d IDENTICAL.%p val.%s %s vs %s val.%s\n",counter,ptr,ptr->item->value,kv777_itemkey(ptr->item),key,value);
            kv777_unlock(kv);
            return(ptr);
        }
        ind = ptr->ind;
        //fprintf(stderr,"%d DELETE.%p val.%s %s vs %s val.%s\n",counter,ptr,ptr->item->value,kv777_itemkey(ptr->item),key,value);
        HASH_DELETE(hh,kv->table,ptr);
        free(ptr);
        counter++;
        duplicate = 1;
    } else ind = kv->numkeys;
    ptr = calloc(1,sizeof(struct kv777_item));
    ptr->ind = ind;
    if ( (ptr->item= kv777_hdditem(&ptr->itemsize,0,0,key,keysize,value,valuesize)) != 0 )
    {
        if ( duplicate == 0 )
            kv->numkeys++;
        HASH_ADD_KEYPTR(hh,kv->table,kv777_itemkey(ptr->item),keysize,ptr);
        if ( kv->hddflag != 0 && kv->rwflag != 0 )
            DL_APPEND(kv->list,ptr);
    }
    else
    {
        printf("kv777_write: couldnt create item.(%s) %s ind.%d offset.%ld\n",key,value,kv->numkeys,ftell(kv->fp));
        free(ptr), ptr = 0;
    }
    kv777_unlock(kv);
    return(ptr);
}

void *kv777_read(struct kv777 *kv,void *key,int32_t keysize,void *value,int32_t *valuesizep)
{
    struct kv777_hdditem *item; struct kv777_item *ptr = 0;
    kv777_lock(kv);
    HASH_FIND(hh,kv->table,key,keysize,ptr);
    kv777_unlock(kv);
    if ( ptr != 0 && (item= ptr->item) != 0 && (item->valuesize & (1<<31)) == 0 )
    {
        if ( item->valuesize <= *valuesizep )
        {
            if ( value != 0 )
                memcpy(value,item->value,item->valuesize);
        }
        *valuesizep = item->valuesize;
        return(item->value);
    }
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

char *kv777_findstr(char *retbuf,int32_t max,struct kv777 *kv,char *key)
{
    return(kv777_read(kv,key,(int32_t)strlen(key)+1,retbuf,&max));
}

struct kv777 *kv777_init(char *name,int32_t hddflag,int32_t multithreaded,int32_t mmapflag) // kv777_init IS NOT THREADSAFE!
{
    long offset = 0; struct kv777_hdditem *item; uint32_t i,itemsize,allocflag;
    struct kv777_item *ptr; struct kv777 *kv;
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
    if ( (kv->fp= fopen(kv->fname,"rb+")) == 0 )
        kv->fp = fopen(kv->fname,"wb+");
    if ( kv->fp != 0 )
    {
        if ( kv->mmapflag != 0 )
        {
            fseek(kv->fp,0,SEEK_END);
            kv->mapsize = ftell(kv->fp);
            kv->fileptr = map_file(kv->fname,&kv->mapsize,0);
        }
        rewind(kv->fp);
        while ( (item= kv777_load(&allocflag,&itemsize,kv)) != 0 )
        {
            //printf("%d: item.%p itemsize.%d\n",kv->numkeys,item,itemsize);
            if ( (item->valuesize & (1<<31)) != 0 && allocflag != 0 )
                free(item);
            else
            {
                ptr = calloc(1,sizeof(*ptr));
                ptr->itemsize = itemsize;
                ptr->item = item;
                ptr->ind = kv->numkeys++;
                ptr->offset = offset;
                HASH_ADD_KEYPTR(hh,kv->table,kv777_itemkey(item),item->keysize,ptr);
                //fprintf(stderr,"[%s] add item.%d crc.%u valuesize.%d keysize.%d [%s]\n",item->value,kv->numkeys,item->crc,item->valuesize,item->keysize,kv777_itemkey(item));
            }
            offset = kv->offset; //ftell(kv->fp);
        }
    }
    printf("kv777.%s added %d items, fpos.%ld -> goodpos.%ld fileptr.%p mapsize.%ld\n",kv->name,kv->numkeys,kv->fp != 0 ? ftell(kv->fp) : 0,offset,kv->fileptr,(long)kv->mapsize);
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

void kv777_test()
{
    struct kv777 *kv; void *rval; int32_t errors,iter,i=1,j,len,keylen,valuesize,n = 1000000; uint8_t key[32],value[32]; double startmilli;
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
                if ( iter != 0 && (i % 1000) == 0 )
                    value[0] ^= 0xff;
                kv777_write(kv,key,keylen,value,valuesize);
                if ( (rval= kv777_read(kv,key,keylen,0,&len)) != 0 )
                {
                    if ( len != valuesize || memcmp(value,rval,valuesize) != 0 )
                        errors++, printf("len.%d vs valuesize.%d or data mismatch\n",len,valuesize);
                } else errors++, printf("kv777_read error i.%d cant find key added, len.%d, valuesize.%d\n",i,len,valuesize);
            }
        }
        printf("iter.%d fileptr.%p finished kv777_test %d iterations, %.4f millis ave -> %.1f seconds\n",iter,kv->fileptr,i,(milliseconds() - startmilli) / i,.001*(milliseconds() - startmilli));
        kv777_flush();
        printf("errors.%d finished kv777_test %d iterations, %.4f millis ave -> %.1f seconds after flush\n",errors,i,(milliseconds() - startmilli) / i,.001*(milliseconds() - startmilli));
    }
    //getchar();
}

#endif
#endif
