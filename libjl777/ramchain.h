//
//  ramchain
//  SuperNET
//
//  by jl777 on 12/29/14.
//  huffman coding based on code from: http://rosettacode.org/wiki/Huffman_coding
//  MIT license

#ifndef ramchain_h
#define ramchain_h

#define SETBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] |= (1 << ((bitoffset) & 7)))
#define GETBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] & (1 << ((bitoffset) & 7)))
#define CLEARBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] &= ~(1 << ((bitoffset) & 7)))

#define MAX_HUFFBITS 6
struct huffentry { uint64_t numbits:MAX_HUFFBITS,bits:(64-MAX_HUFFBITS); };

struct huffnode
{
	struct huffnode *left,*right;
	uint32_t freq,ind;
};

struct huffcode
{
    //struct huffentry *code;
    struct huffitem *items;
    struct huffnode **qqq,**q;
    int32_t numinds,maxbits,n_nodes,qend,totalbits,totalbytes,numnodes,maxind;
    struct huffnode pool[];
};

/*struct ramchain_info
{
    int32_t blocknum_bits,txind_bits,vout_bits;
};
struct ramchain_entry { uint64_t value; uint32_t outblock:20,txind:15,vout:14,spentblock:20,spentind:15,vin:14; };
*/

void hclose(HUFF *hp)
{
    if ( hp != 0 )
        free(hp);
}

HUFF *hopen(uint8_t *bits,int32_t num)
{
    HUFF *hp = calloc(1,sizeof(*hp));
    hp->ptr = hp->buf = bits;
    if ( (num & 7) != 0 )
        num++;
    hp->allocsize = num;
    return(hp);
}

void _hseek(HUFF *hp)
{
    hp->ptr = &hp->buf[hp->bitoffset >> 3];
    hp->maski = (hp->bitoffset & 7);
}

void hrewind(HUFF *hp)
{
    hp->bitoffset = 0;
    _hseek(hp);
}

void hclear(HUFF *hp)
{
    hp->bitoffset = 0;
    _hseek(hp);
    memset(hp->buf,0,hp->allocsize);
    hp->endpos = 0;
}

int32_t hseek(HUFF *hp,int32_t offset,int32_t mode)
{
    if ( mode == SEEK_END )
        offset += hp->endpos;
    if ( offset >= 0 && (offset>>3) < hp->allocsize )
        hp->bitoffset = offset, _hseek(hp);
    else
    {
        printf("hseek.%d: illegal offset.%d >= allocsize.%d\n",mode,offset,hp->allocsize);
        return(-1);
    }
    return(0);
}

int32_t hgetbit(HUFF *hp)
{
    int32_t bit = 0;
    if ( hp->bitoffset < hp->endpos )
    {
        if ( (*hp->ptr & huffmasks[hp->maski++]) != 0 )
            bit = 1;
        hp->bitoffset++;
        if ( hp->maski == 8 )
        {
            hp->maski = 0;
            hp->ptr++;
        }
        return(bit);
    }
    return(-1);
}

int32_t hputbit(HUFF *hp,int32_t bit)
{
    if ( bit != 0 )
        *hp->ptr |= huffmasks[hp->maski];
    else *hp->ptr &= huffoppomasks[hp->maski];
    if ( ++hp->maski >= 8 )
    {
        hp->maski = 0;
        hp->ptr++;
    }
    if ( ++hp->bitoffset > hp->endpos )
        hp->endpos = hp->bitoffset;
    if ( (hp->bitoffset>>3) >= hp->allocsize )
    {
        printf("hwrite: bitoffset.%d >= allocsize.%d\n",hp->bitoffset,hp->allocsize);
        _hseek(hp);
        return(-1);
    }
    return(0);
}

int32_t hwrite(uint64_t codebits,int32_t numbits,HUFF *hp)
{
    int32_t i;
    for (i=0; i<numbits; i++,codebits>>=1)
    {
        if ( hputbit(hp,codebits & 1) < 0 )
            return(-1);
    }
    return(numbits);
}

long emit_varint(FILE *fp,uint64_t x)
{
    uint8_t b; uint16_t s; uint32_t i;
    long retval = -1;
    if ( x < 0xfd )
        b = x, retval = fwrite(&b,1,sizeof(b),fp);
    else
    {
        switch ( x )
        {
            case 0xfd: s = x, retval = fwrite(&s,1,sizeof(s),fp); break;
            case 0xfe: i = (uint32_t)x, retval = fwrite(&i,1,sizeof(i),fp); break;
            case 0xff: retval = fwrite(&x,1,sizeof(x),fp); break;
            default: printf("impossible switch val %llx\n",(long long)x); break;
        }
    }
    return(retval);
}

int32_t hflush(FILE *fp,HUFF *hp)
{
    uint32_t len;
    if ( emit_varint(fp,hp->endpos) < 0 )
        return(-1);
    len = hp->endpos >> 3;
    if ( (hp->endpos & 7) != 0 )
        len++;
    if ( fwrite(hp->buf,1,len,fp) != len )
        return(-1);
    return(0);
}

void huff_free(struct huffcode *huff)
{
    //if ( huff->qqq != 0 )
    //    free(huff->qqq);
    if ( huff->items != 0 )
        free(huff->items);
    free(huff);
}

void huff_iteminit(struct huffitem *hip,void *ptr,int32_t size,int32_t isptr,int32_t ishex)
{
    memcpy(hip->U.bits.bytes,ptr,size);
    hip->size = size;
    hip->isptr = isptr;
    hip->ishex = ishex;
}

void *huff_getitem(struct huffcode *huff,int32_t *sizep,uint32_t ind)
{
    static unsigned char defaultbytes[256];
    struct huffitem *hip;
    int32_t i;
    if ( huff != 0 )
    {
        hip = &huff->items[ind];
        *sizep = hip->size;
        return(hip->U.bits.bytes);
    }
    if ( defaultbytes[0xff] != 0xff )
        for (i=0; i<256; i++)
            defaultbytes[i] = i;
    *sizep = 1;
    return(&defaultbytes[ind & 0xff]);
}

int32_t huff_output(struct huffcode *huff,uint8_t *output,int32_t num,int32_t maxlen,int32_t ind)
{
    int32_t size;
    void *ptr;
    ptr = huff_getitem(huff,&size,ind);
    if ( num+size <= maxlen )
    {
        //printf("%d.(%d %c) ",size,ind,*(char *)ptr);
        memcpy(output + num,ptr,size);
        return(num+size);
    }
    printf("huffoutput error: num.%d size.%d > maxlen.%d\n",num,size,maxlen);
    return(-1);
}

uint64_t _reversebits(uint64_t x,int32_t n)
{
    uint64_t rev = 0;
    int32_t i = 0;
    while ( n > 0 )
    {
        if ( GETBIT((void *)&x,n-1) != 0 )
            SETBIT(&rev,i);
        i++;
        n--;
    }
    return(rev);
}

uint64_t huff_convstr(char *str)
{
    uint64_t mask,codebits = 0;
    long n = strlen(str);
    mask = (1 << (n-1));
    while ( n > 0 )
    {
        if ( str[n-1] != '0' )
            codebits |= mask;
        //printf("(%c %llx m%x) ",str[n-1],(long long)codebits,(int)mask);
        mask >>= 1;
        n--;
    }
    //printf("(%s -> %llx)\n",str,(long long)codebits);
    return(codebits);
}

char *huff_str(uint64_t codebits,int32_t n)
{
    static char str[128];
    uint64_t mask = 1;
    int32_t i;
    for (i=0; i<n; i++,mask<<=1)
        str[i] = ((codebits & mask) != 0) + '0';
    str[i] = 0;
    return(str);
}

struct huffnode *huff_leafnode(struct huffcode *huff,uint32_t ind)
{
	struct huffnode *leaf = 0;
    uint32_t freq;
	if ( (freq= huff->items[ind].freq) != 0 )
    {
        leaf = huff->pool + huff->n_nodes++;
        leaf->ind = ind, leaf->freq = freq;
        if ( ind > huff->maxind )
            huff->maxind = ind;
    }
	return(leaf);
}

struct huffheap
{
    uint32_t *f;
    uint32_t *h,n,s,cs,pad;
};
typedef struct huffheap heap_t;

heap_t *_heap_create(uint32_t s,uint32_t *f)
{
    heap_t *h;
    h = malloc(sizeof(heap_t));
    h->h = malloc(sizeof(*h->h) * s);
   // printf("_heap_create heap.%p h.%p s.%d\n",h,h->h,s);
    h->s = h->cs = s;
    h->n = 0;
    h->f = f;
    return(h);
}

void _heap_destroy(heap_t *heap)
{
    free(heap->h);
    free(heap);
}

#define swap_(I,J) do { int t_; t_ = a[(I)];	\
a[(I)] = a[(J)]; a[(J)] = t_; } while(0)
void _heap_sort(heap_t *heap)
{
    uint32_t i=1,j=2; // gnome sort
    uint32_t *a = heap->h;
    while ( i < heap->n ) // smaller values are kept at the end
    {
        if ( heap->f[a[i-1]] >= heap->f[a[i]] )
            i = j, j++;
        else
        {
            swap_(i-1, i);
            i--;
            i = (i == 0) ? j++ : i;
        }
    }
}
#undef swap_

void _heap_add(heap_t *heap,uint32_t ind)
{
    //printf("add to heap ind.%d n.%d s.%d\n",ind,heap->n,heap->s);
    if ( (heap->n + 1) > heap->s )
    {
        heap->h = realloc(heap->h,heap->s + heap->cs);
        heap->s += heap->cs;
    }
    heap->h[heap->n++] = ind;
    _heap_sort(heap);
}

int32_t _heap_remove(heap_t *heap)
{
    if ( heap->n > 0 )
        return(heap->h[--heap->n]);
    return(-1);
}

void huff_insert(struct huffcode *huff,struct huffnode *node)
{
	int j, i;
    if ( node != 0 )
    {
        i = huff->qend++;
        while ( (j= (i >> 1)) )
        {
            if ( huff->q[j]->freq <= node->freq )
                break;
            huff->q[i] = huff->q[j], i = j;
        }
        huff->q[i] = node;
    }
}

struct huffnode *huff_newnode(struct huffcode *huff,uint32_t freq,uint32_t ind,struct huffnode *a,struct huffnode *b)
{
	struct huffnode *n = 0;
	if ( freq == 0 )
    {
        if ( a == 0 || b == 0 )
        {
            printf("huff_newnode null a.%p or b.%p\n",a,b);
            while ( 1 ) sleep(1);
        }
        n = huff->pool + huff->n_nodes++;
		n->left = a, n->right = b;
		n->freq = a->freq + b->freq;
	}
    else
    {
        printf("huff_newnode called with freq.%d ind.%d\n",freq,ind);
        while ( 1 )
            sleep(1);
    }
	return(n);
}

struct huffnode *huff_remove(struct huffcode *huff)
{
	int l,i = 1;
	struct huffnode *n = huff->q[i];
   // printf("remove: set n <- q[i %d].%d\n",i,huff->q[i]->ind);
	if ( huff->qend < 2 )
    {
        printf("huff->qend.%d null return\n",huff->qend); while ( 1 ) sleep(1);
        return(0);
    }
	huff->qend--;
	while ( (l= (i << 1)) < huff->qend )
    {
		if ( (l + 1) < huff->qend && huff->q[l + 1]->freq < huff->q[l]->freq )
            l++;
		huff->q[i] = huff->q[l], i = l;
	}
	huff->q[i] = huff->q[huff->qend];
	return(n);
}


// huffmann code generator
struct huffentry *create_huffman_codes(int32_t **predsp,int32_t *maxbitsp,uint32_t *freqs,int32_t numinds)
{
    int32_t *preds,bn,pred,ix,r1,r2,i,extf;
    int32_t maxbits,maxind;
    struct huffentry *codes;
    uint64_t bc;
    uint32_t *efreqs;
    heap_t *heap;
    *predsp = 0;
    extf = numinds;
    efreqs = calloc(2 * numinds,sizeof(*efreqs));
    preds = calloc(2 * numinds+1,sizeof(*preds));
    memcpy(efreqs,freqs,sizeof(*efreqs) * numinds);
    memset(&efreqs[numinds],0,sizeof(*efreqs) * numinds);
    if ( (heap= _heap_create(numinds*2,efreqs)) == NULL )
    {
        free(efreqs);
        free(preds);
        *maxbitsp = 0;
        return(NULL);
    }
    //printf("heap.%p h.%p s.%d\n",heap,heap->h,heap->s);
    for (i=0; i<numinds; i++)
    {
        //printf("i.%d: [%d] heap.%p h.%p s.%d\n",i,efreqs[i],heap,heap->h,heap->s);
        if ( efreqs[i] > 0 )
            _heap_add(heap,i);
    }
    //for (i=0; i<numinds; i++)
    //    if ( heap->h[i] != 0 )
    //        printf("(%d: %d) ",heap->h[i],efreqs[heap->h[i]]);
    //printf("starting heap\n");
    while ( heap->n > 1 )
    {
        r1 = _heap_remove(heap);
        r2 = _heap_remove(heap);
        efreqs[extf] = (efreqs[r1] + efreqs[r2]);
        _heap_add(heap,extf);
        preds[r1] = extf;
        preds[r2] = -extf;
        printf("r1.%d (%d) <- %d | r2.%d (%d) <- %d\n",r1,efreqs[r1],extf,r2,efreqs[r2],-extf);
        extf++;
    }
    r1 = _heap_remove(heap);
    for (i=0; i<numinds; i++)
        printf("(%d: %d) ",heap->h[i],efreqs[heap->h[i]]);
    printf("ending heap\n");
    preds[r1] = r1;
    preds[2*numinds] = r1;
    for (i=0; i<=2*numinds; i++)
        if ( preds[i] != 0 )
            printf("%d: (%4d %4d) [%d %d]\n",i,preds[i],efreqs[i],abs(preds[i])-numinds,-(abs(preds[i]) - numinds));
    printf("preds\n");
    _heap_destroy(heap);
    codes = calloc(sizeof(*codes),numinds);
    for (i=maxbits=maxind=0; i<numinds; i++)
    {
        bc = bn = 0;
        if ( efreqs[i] != 0 )
        {
            ix = i;
            pred = preds[ix];
            while ( pred != ix && -pred != ix )
            {
                if ( pred >= 0 )
                {
                    bc |= (1L << bn);
                    ix = pred;
                }
                else ix = -pred;
                pred = preds[ix];
                bn++;
            }
            codes[i].numbits = bn;
            codes[i].bits = _reversebits(bc,bn);
            if ( bn > maxbits )
                maxbits = bn;
            maxind = i;
        }
    }
    //00116 (t): (17).5 10111
    //1110101110011100000000111000000010011000001011001101001010111111111001010000010101111100000011110010001000101010010011000001011100110110110110000011110011001hgetbit
    //free(preds);
    free(efreqs);
    *maxbitsp = maxbits;
    if ( maxbits >= (1<<MAX_HUFFBITS) )
    {
        printf("maxbits.%d wont fit in (1 << MAX_HUFFBITS.%d)\n",maxbits,MAX_HUFFBITS);
        free(codes);
        free(preds);
        return(0);
    }
    *predsp = preds;
    return(codes);
}

int32_t hdecode(struct huffcode *huff,uint8_t *output,int32_t maxlen,HUFF *hp,struct huffentry *codes,int32_t *preds,int32_t numinds)
{
    int32_t ix,c,num = 0;
    ix = preds[2*numinds];
    output[0] = 0;
    return(0);
	while ( (c= hgetbit(hp)) >= 0 )
    {
		if ( c == 0 )
            ix = preds[ix];
		else ix = preds[-ix];
		if ( ix != 0 )
        {
            if ( (num = huff_output(huff,output,num,maxlen,ix)) < 0 )
                return(-1);
        }
	}
    printf("(%s) huffdecode num.%d\n",output,num);
    return(num);
}

void huff_buildcode(struct huffcode *huff,struct huffnode *n,char *s,int32_t len)
{
	static char buf[1024],*out = buf;
    uint64_t codebits;
    uint32_t ind;
    if ( n == 0 )
    {
        printf("huff_buildcode null n\n");
        while ( 1 ) sleep(1);
    }
	if ( (ind= n->ind) != 0 ) // leaf node
    {
        if ( ind <= huff->numinds )
        {
            s[len] = 0;
            strcpy(out,s);
            codebits = huff_convstr(out);
            huff->numnodes++;
            huff->items[ind].codebits = codebits;
            huff->items[ind].numbits = len;
            huff->totalbits += len * huff->items[ind].freq;
            huff->totalbytes += huff->items[ind].size * huff->items[ind].freq;
            if ( len > huff->maxbits )
                huff->maxbits = len;
            if ( ind > huff->maxind )
                huff->maxind = ind;
            out += len + 1;
            fprintf(stderr,"%6d: %8s (%12s).%-2d | nodes.%d bytes.%d -> bits.%d %.3f\n",ind,out,huff_str(codebits,len),len,huff->numnodes,huff->totalbytes,huff->totalbits,((double)huff->totalbytes*8)/huff->totalbits);
            return;
        } else printf("FATAL: ind.%d overflow vs numinds.%d\n",ind,huff->numinds);
    }
    else // combo node
    {
        s[len] = '0'; huff_buildcode(huff,n->left,s,len + 1);
        s[len] = '1'; huff_buildcode(huff,n->right,s,len + 1);
    }
}

/*
 Create a leaf node for each symbol and add it to the priority queue.
While there is more than one node in the queue:
Remove the node of highest priority (lowest probability) twice to get two nodes.
Create a new internal node with these two nodes as children and with probability equal to the sum of the two nodes' probabilities.
Add the new node to the queue.
The remaining node is the root node and the tree is complete.
*/

void inttobits(uint64_t c,int32_t n,char *s)
{
    s[n] = 0;
    while ( n > 0 )
    {
        s[n-1] = (c%2) + '0';
        c >>= 1;
        n--;
    }
}

int32_t emit_bitstream(uint8_t *bits,int32_t bitpos,uint32_t raw,struct huffentry *r,int32_t maxind)
{
    int32_t i,n = 0;
    uint64_t codebits;
    if ( raw < maxind )
    {
        n = r[raw].numbits;
        codebits = r[raw].bits;
        for (i=0; i<n; i++,codebits>>=1,bitpos++)
        {
            printf("%c",(char)((codebits & 1) + '0'));
            if ( (codebits & 1) != 0 )
                SETBIT(bits,bitpos);
        }
    } else printf("raw.%u >= maxind.%d\n",raw,maxind);
    return(n);
}

struct huffentry *teststuff(char *str,struct huffitem *items,int32_t numinds)
{
    char *strbit;
    struct huffentry *codes;
    uint8_t bits[1024],bits2[1024],test[128];
    int32_t i,c,n,len,num,maxbits,*preds;
    uint32_t *freqs;
    uint64_t codebits;
    HUFF *hp;
    double startmilli = milliseconds();
    numinds = 4;
    freqs = calloc(1,sizeof(*freqs) * numinds);
    str = "01111112223";
    len = (int32_t)strlen(str);
    for (i=0; i<len; i++)
    {
        test[i] = str[i] - '0';
        freqs[test[i]]++;
    }
    str = (char *)test;
    //for (ind=0; ind<numinds; ind++)
    //    freqs[ind] = items[ind].freq;
    codes = create_huffman_codes(&preds,&maxbits,freqs,numinds);

    printf("elapsed time %.3f millis (%s)\n",milliseconds() - startmilli,str);
    strbit = calloc(1,maxbits);
    for (i=0; i<numinds; i++)
    {
        n = codes[i].numbits;
        codebits = _reversebits(codes[i].bits,n);
        if ( n != 0 )
        {
            inttobits(codebits,n,strbit);
            printf("%05d (%c): (%8s).%d %s\n",i,i,huff_str(codebits,n),n,strbit);
        }
    }
    free(strbit);

    memset(bits,0,sizeof(bits));
    memset(bits2,0,sizeof(bits2));
    for (i=num=0; i<len; i++)
        num += emit_bitstream(bits,num,test[i],codes,numinds);
    printf("\nnuminds.%d maxbits.%d num for str.%d vs %d\n",numinds,maxbits,num,len*8);
    for (i=0; i<num; i++)
        printf("%c",(GETBIT(bits,i) != 0) + '0');
    printf("\n");
    hp = hopen(bits2,num);
    for (i=num=0; i<len; i++)
    {
        c = test[i];
        codebits = codes[c].bits;
        num += hwrite(codebits,codes[c].numbits,hp);
        //printf("(%d %d) ",i,r[c].numbits);
    }
    printf("\n");
    for (i=0; i<num; i++)
        printf("%c",(GETBIT(bits2,i) != 0) + '0');
    printf("bits2 num.%d\n",num);
    hrewind(hp);
    for (i=0; i<num; i++)
        printf("%c",(hgetbit(hp) + '0'));
    printf("hgetbit num.%d\n",num);
    hrewind(hp);
    uint8_t output[8192];
    num = hdecode(0,output,(int32_t)sizeof(output),hp,codes,preds,numinds);
    return(codes);
}

struct huffcode *huff_init(struct huffitem *items,int32_t numinds)
{
    struct huffcode *huff;
    uint32_t ind,nonz;
   	char c[1024];
    huff = calloc(numinds,sizeof(*huff) + (sizeof(*huff->pool)));
    huff->items = items;
    huff->numinds = numinds;
    huff->qend = 1;
    huff->qqq = calloc(1,sizeof(*huff->qqq) * numinds);
    huff->q = huff->qqq - 1;

	for (ind=0; ind<numinds; ind++)
        huff_insert(huff,huff_leafnode(huff,ind));
    printf("inserted qend.%d maxin.%d\n",huff->qend,huff->maxind);
    for (ind=nonz=0; ind<numinds; ind++)
        if ( huff->q[ind] != 0 )
            printf("(%p %p %d).%d ",huff->q[ind]->left,huff->q[ind]->right,huff->q[ind]->freq,huff->q[ind]->ind), nonz++;
    printf("nonz.%d\n",nonz);
    while ( huff->qend > 2 )
		huff_insert(huff,huff_newnode(huff,0,0,huff_remove(huff),huff_remove(huff)));
    printf("coalesced\n");
    for (ind=nonz=0; ind<numinds; ind++)
        if ( huff->q[ind] != 0 )
            printf("(%p %p %d).%d ",huff->q[ind]->left,huff->q[ind]->right,huff->q[ind]->freq,huff->q[ind]->ind), nonz++;
    printf("nonz.%d\n",nonz);
    huff_buildcode(huff,huff->q[1],c,0);
    huff->numinds++;
    if ( huff->maxbits >= (1<<MAX_HUFFBITS) )
    {
        printf("maxbits.%d wont fit in (1 << MAX_HUFFBITS.%d)\n",huff->maxbits,MAX_HUFFBITS);
        huff_free(huff);
        return(0);
    }
    return(huff);
}

int32_t huffencode(struct huffcode *huff,HUFF *hp,char *s)
{
    uint64_t codebits;
    int32_t i,n,count = 0;
	while ( *s )
    {
        codebits = huff->items[(int)*s].codebits;
        n = huff->items[(int)*s].numbits;
        for (i=0; i<n; i++,codebits>>=1)
            hputbit(hp,codebits & 1);
        count += n;
        s++;
	}
    return(count);
}

int32_t huffdecode(struct huffcode *huff,uint8_t *output,int32_t maxlen,HUFF *hp,struct huffnode *t)
{
    int32_t c,num = 0;
	struct huffnode *n = t;
	while ( (c= hgetbit(hp)) >= 0 )
    {
		if ( c == 0 )
            n = n->left;
		else n = n->right;
		if ( n->ind != 0 )
        {
            if ( (num = huff_output(huff,output,num,maxlen,n->ind)) < 0 )
                return(-1);
            n = t;
        }
	}
    printf("(%s) huffdecode num.%d\n",output,num);
	if ( t != n )
        printf("garbage input\n");
    return(num);
}

int testhuffcode(char *str,struct huffitem *items,int32_t numinds)
{
    uint8_t bits2[8192],output[8192];
    struct huffcode *huff;
    struct huffentry *codes;
    int i,num;
    HUFF *hp;
    double endmilli,startmilli = milliseconds();
	codes = teststuff(str,items,numinds);
    return(0);

    huff = huff_init(items,numinds);
    endmilli = milliseconds();
	//for (i=0; i<numinds; i++)
	//	if ( huff->code[i].numbits != 0 )
    //        printf("'%c': %llx.%d\n",i,(long long)huff->code[i].bits,huff->code[i].numbits);
    printf("%.3f millis to encode\n",endmilli-startmilli);
    hp = hopen(bits2,sizeof(bits2));
    num = huffencode(huff,hp,str);
	printf("encoded: %s\n",str);
    for (i=0; i<num; i++)
        printf("%c",(GETBIT(bits2,i) != 0) + '0');
    printf(" bits2 num.%d\n",num);
    hrewind(hp);
    for (i=0; i<num; i++)
        printf("%c",(hgetbit(hp) + '0'));
    printf(" hgetbit num.%d\n",num);

	printf("decoded: ");
    startmilli = milliseconds();
    hrewind(hp);
    num = huffdecode(huff,output,sizeof(output),hp,huff->q[1]);
    endmilli = milliseconds();
    output[num] = 0;
    huff_free(huff);
    hclose(hp);
    printf("%s\nnum.%d %.3f millis\n",output,num,endmilli - startmilli);
	return(0);
}



#endif
