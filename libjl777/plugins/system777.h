//
//  system777.h
//  crypto777
//
//  Created by James on 4/9/15.
//  Copyright (c) 2015 jl777. All rights reserved.
//

#ifdef DEFINES_ONLY
#ifndef crypto777_system777_h
#define crypto777_system777_h

#ifdef _WIN32
#include "mman-win.h"
#include <io.h>
#include <share.h>
#include <errno.h>
#include <string.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/time.h>
#include "utils/utils777.c"
#include "../includes/mutex.h"
#include "../includes/utlist.h"
#include "../includes/uv.h"

#define portable_mutex_t struct nn_mutex
#define portable_mutex_init nn_mutex_init
#define portable_mutex_lock nn_mutex_lock
#define portable_mutex_unlock nn_mutex_unlock
#define portable_thread_t uv_thread_t

typedef struct queue
{
	struct queueitem *list;
	portable_mutex_t mutex;
    char name[31],initflag;
} queue_t;
void lock_queue(queue_t *queue);
void queue_enqueue(char *name,queue_t *queue,struct queueitem *item);
void *queue_dequeue(queue_t *queue,int32_t offsetflag);
int32_t queue_size(queue_t *queue);
struct queueitem *queueitem(char *str);
void free_queueitem(void *itemptr);

struct nn_clock
{
    uint64_t last_tsc;
    uint64_t last_time;
};
void nn_clock_init (struct nn_clock *self);
void nn_clock_term (struct nn_clock *self);
uint64_t nn_clock_now (struct nn_clock *self);
uint64_t nn_clock_timestamp ();

void nn_sleep (int milliseconds);
void sleep777(uint32_t seconds);
void usleep777(uint32_t microseconds);
double milliseconds(void);
void randombytes(unsigned char *x,int xlen);
void *portable_thread_create(void *funcp,void *argp);

struct mappedptr
{
	char fname[512];
	void *fileptr,*pending;
	uint64_t allocsize,changedsize;
	int32_t rwflag,actually_allocated;
};
void *alloc_aligned_buffer(uint64_t allocsize);
void *map_file(char *fname,uint64_t *filesizep,int32_t enablewrite);
int32_t release_map_file(void *ptr,uint64_t filesize);
void close_mappedptr(struct mappedptr *mp);
int32_t open_mappedptr(struct mappedptr *mp);
void sync_mappedptr(struct mappedptr *mp,uint64_t len);
void ensure_filesize(char *fname,long filesize);
void *init_mappedptr(void **ptrp,struct mappedptr *mp,uint64_t allocsize,int32_t rwflag,char *fname);
void ensure_dir(char *dirname); // jl777: does this work in windows?
int32_t compare_files(char *fname,char *fname2); // OS portable
long copy_file(char *src,char *dest); // OS portable
void delete_file(char *fname,int32_t scrubflag);

struct alloc_space { void *ptr; long used,size; };
void ram_clear_alloc_space(struct alloc_space *mem);
void *memalloc(struct alloc_space *mem,long size);
void *permalloc(char *coinstr,struct alloc_space *mem,long size,int32_t selector);


#endif
#endif
