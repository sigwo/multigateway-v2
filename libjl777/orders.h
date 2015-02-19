//
//  orders.h
//
//  Created by jl777 on 7/9/14.
//  Copyright (c) 2014 jl777. All rights reserved.
//

#ifndef xcode_orders_h
#define xcode_orders_h

#define _ASKMASK (1L << 0)
#define _FLIPMASK (1L << 1)
#define _TYPEMASK (~(_ASKMASK|_FLIPMASK))
#define _obookid(baseid,relid) ((baseid) ^ (relid))
#define _iQ_flipped(iQ) (((iQ)->type & _FLIPMASK) ? 1 : 0)
#define _iQ_dir(iQ) ((((iQ)->type) & _ASKMASK) ? -1 : 1)
#define _iQ_type(iQ) ((iQ)->type & _TYPEMASK)
#define _iQ_price(iQ) ((double)(iQ)->relamount / (iQ)->baseamount)
#define _iQ_volume(iQ) ((double)(iQ)->baseamount / SATOSHIDEN)

char *assetmap[][2] =
{
    { "5527630", "NXT" },
    { "17554243582654188572", "BTC" },
    { "4551058913252105307", "BTC" },
    { "12659653638116877017", "BTC" },
    { "11060861818140490423", "BTCD" },
    { "6918149200730574743", "BTCD" },
    { "13120372057981370228", "BITS" },
    { "2303962892272487643", "DOGE" },
    { "16344939950195952527", "DOGE" },
    { "6775076774325697454", "OPAL" },
    { "7734432159113182240", "VPN" },
    { "9037144112883608562", "VRC" },
    { "1369181773544917037", "BBR" },
    { "17353118525598940144", "DRK" },
    { "2881764795164526882", "LTC" },
    { "7117580438310874759", "BC" },
    { "275548135983837356", "VIA" },
};

struct rambook_info
{
    UT_hash_handle hh;
    struct InstantDEX_quote *quotes;
    uint64_t baseid,relid,obookid;
    int32_t numquotes,maxquotes;
} *Rambooks;

void set_assetname(char *name,uint64_t assetbits)
{
    char assetstr[64];
    int32_t i,creatededflag;
    struct NXT_asset *ap;
    expand_nxt64bits(assetstr,assetbits);
    for (i=0; i<(int32_t)(sizeof(assetmap)/sizeof(*assetmap)); i++)
    {
        if ( strcmp(assetmap[i][0],assetstr) == 0 )
        {
            strcpy(name,assetmap[i][1]);
            return;
        }
    }
    ap = get_NXTasset(&creatededflag,Global_mp,assetstr);
    strcpy(name,ap->name);
}

cJSON *rambook_json(struct rambook_info *rb)
{
    cJSON *json = cJSON_CreateObject();
    char numstr[64],base[512],rel[512];
    set_assetname(base,rb->baseid);
    cJSON_AddItemToObject(json,"base",cJSON_CreateString(base));
    sprintf(numstr,"%llu",(long long)rb->baseid), cJSON_AddItemToObject(json,"baseid",cJSON_CreateString(numstr));
    set_assetname(rel,rb->relid);
    cJSON_AddItemToObject(json,"rel",cJSON_CreateString(rel));
    sprintf(numstr,"%llu",(long long)rb->relid), cJSON_AddItemToObject(json,"relid",cJSON_CreateString(numstr));
    cJSON_AddItemToObject(json,"numquotes",cJSON_CreateNumber(rb->numquotes));
    return(json);
}

struct rambook_info *get_rambook(uint64_t baseid,uint64_t relid)
{
    uint64_t obookid;
    struct rambook_info *rb;
    obookid = _obookid(baseid,relid);
    HASH_FIND(hh,Rambooks,&obookid,sizeof(obookid),rb);
    if ( rb == 0 )
    {
        rb = calloc(1,sizeof(*rb));
        rb->obookid = obookid;
        if ( baseid < relid )
        {
            rb->baseid = baseid;
            rb->relid = relid;
        }
        else
        {
            rb->baseid = relid;
            rb->relid = baseid;
        }
        HASH_ADD(hh,Rambooks,obookid,sizeof(obookid),rb);
    }
    return(rb);
}

struct rambook_info **get_allrambooks(int32_t *numbooksp)
{
    int32_t i = 0;
    struct rambook_info *rb,*tmp,**obooks;
    *numbooksp = HASH_COUNT(Rambooks);
    obooks = calloc(*numbooksp,sizeof(*rb));
    HASH_ITER(hh,Rambooks,rb,tmp)
        obooks[i++] = rb;
    if ( i != *numbooksp )
        printf("get_allrambooks HASH_COUNT.%d vs i.%d\n",*numbooksp,i);
    return(obooks);
}

cJSON *all_orderbooks()
{
    cJSON *array,*json = 0;
    struct rambook_info **obooks;
    int32_t i,numbooks;
    if ( (obooks= get_allrambooks(&numbooks)) != 0 )
    {
        array = cJSON_CreateArray();
        for (i=0; i<numbooks; i++)
            cJSON_AddItemToArray(array,rambook_json(obooks[i]));
        free(obooks);
        json = cJSON_CreateObject();
        cJSON_AddItemToObject(json,"orderbooks",array);
    }
    return(json);
}

uint64_t find_best_market_maker() // store ranked list
{
    char cmdstr[1024],NXTaddr[64],receiverstr[MAX_JSON_FIELD],*jsonstr;
    cJSON *json,*array,*txobj;
    int32_t i,n,createdflag;
    struct NXT_acct *np,*maxnp = 0;
    uint64_t amount,senderbits;
    uint32_t now = (uint32_t)time(NULL);
    sprintf(cmdstr,"requestType=getAccountTransactions&account=%s&timestamp=%u&type=0&subtype=0",INSTANTDEX_ACCT,38785003);
    if ( (jsonstr= bitcoind_RPC(0,"curl",NXTAPIURL,0,0,cmdstr)) != 0 )
    {
       // mm string.({"requestProcessingTime":33,"transactions":[{"fullHash":"2a2aab3b84dadf092cf4cedcd58a8b5a436968e836338e361c45651bce0ef97e","confirmations":203,"signatureHash":"52a4a43d9055fe4861b3d13fbd03a42fecb8c9ad4ac06a54da7806a8acd9c5d1","transaction":"711527527619439146","amountNQT":"1100000000","transactionIndex":2,"ecBlockHeight":360943,"block":"6797727125503999830","recipientRS":"NXT-74VC-NKPE-RYCA-5LMPT","type":0,"feeNQT":"100000000","recipient":"4383817337783094122","version":1,"sender":"423766016895692955","timestamp":38929220,"ecBlockId":"10121077683890606382","height":360949,"subtype":0,"senderPublicKey":"4e5bbad625df3d536fa90b1e6a28c3f5a56e1fcbe34132391c8d3fd7f671cb19","deadline":1440,"blockTimestamp":38929430,"senderRS":"NXT-8E6V-YBWH-5VMR-26ESD","signature":"4318f36d9cf68ef0a8f58303beb0ed836b670914065a868053da5fe8b096bc0c268e682c0274e1614fc26f81be4564ca517d922deccf169eafa249a88de58036"}]})
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (array= cJSON_GetObjectItem(json,"transactions")) != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    txobj = cJSON_GetArrayItem(array,i);
                    copy_cJSON(receiverstr,cJSON_GetObjectItem(txobj,"recipient"));
                    if ( strcmp(receiverstr,INSTANTDEX_ACCT) == 0 )
                    {
                        if ( (senderbits = get_API_nxt64bits(cJSON_GetObjectItem(txobj,"sender"))) != 0 )
                        {
                            expand_nxt64bits(NXTaddr,senderbits);
                            np = get_NXTacct(&createdflag,Global_mp,NXTaddr);
                            amount = get_API_nxt64bits(cJSON_GetObjectItem(txobj,"amountNQT"));
                            if ( np->timestamp != now )
                            {
                                np->quantity = 0;
                                np->timestamp = now;
                            }
                            np->quantity += amount;
                            if ( maxnp == 0 || np->quantity > maxnp->quantity )
                                maxnp = np;
                        }
                    }
                }
            }
            free_json(json);
        }
        free(jsonstr);
    }
    if ( maxnp != 0 )
    {
        printf("Best MM %llu total %.8f\n",(long long)maxnp->H.nxt64bits,dstr(maxnp->quantity));
        return(maxnp->H.nxt64bits);
    }
    return(0);
}

int32_t calc_users_maxopentrades(uint64_t nxt64bits)
{
    return(13);
}

int32_t get_top_MMaker(struct pserver_info **pserverp)
{
    static uint64_t bestMMbits;
    struct nodestats *stats;
    char ipaddr[64];
    *pserverp = 0;
    if ( bestMMbits == 0 )
        bestMMbits = find_best_market_maker();
    if ( bestMMbits != 0 )
    {
        stats = get_nodestats(bestMMbits);
        expand_ipbits(ipaddr,stats->ipbits);
        (*pserverp) = get_pserver(0,ipaddr,0,0);
        return(0);
    }
    return(-1);
}

void purge_oldest_order(struct rambook_info *rb,struct orderbook_tx *tx) // allow one pair per orderbook
{
    int32_t oldi;
    uint32_t i,oldest = 0;
    if ( rb->numquotes == 0 )
        return;
    oldi = -1;
    for (i=0; i<rb->numquotes; i++)
    {
        if ( rb->quotes[i].nxt64bits == tx->iQ.nxt64bits && (oldest == 0 || rb->quotes[i].timestamp < oldest) )
        {
            oldest = rb->quotes[i].timestamp;
            oldi = i;
        }
    }
    if ( oldi >= 0 )
    {
        printf("purge_oldest_order from NXT.%llu oldi.%d timestamp %u\n",(long long)tx->iQ.nxt64bits,oldi,oldest);
        rb->quotes[oldi] = rb->quotes[--rb->numquotes];
        memset(&rb->quotes[rb->numquotes],0,sizeof(rb->quotes[rb->numquotes]));
    }
}

void add_user_order(struct rambook_info *rb,struct InstantDEX_quote *iQ)
{
    int32_t i;
    if ( rb->numquotes > 0 )
    {
        for (i=0; i<rb->numquotes; i++)
        {
            if ( memcmp(iQ,&rb->quotes[i],sizeof(rb->quotes[i])) == 0 )
                break;
        }
    } else i = 0;
    //printf("add_user_order i.%d numquotes.%d\n",i,rb->numquotes);
    if ( i == rb->numquotes )
    {
        if ( i >= rb->maxquotes )
        {
            rb->maxquotes += 1024;
            rb->quotes = realloc(rb->quotes,rb->maxquotes * sizeof(*rb->quotes));
            memset(&rb->quotes[i],0,1024 * sizeof(*rb->quotes));
        }
        rb->quotes[rb->numquotes++] = *iQ;
    }
}

struct InstantDEX_quote *get_matching_quotes(int32_t *numquotesp,uint64_t baseid,uint64_t relid)
{
    struct rambook_info *rb;
    rb = get_rambook(baseid,relid);
    *numquotesp = rb->numquotes;
    printf("get_matching_quotes returns numquotes.%d\n",rb->numquotes);
    return(rb->quotes);
}

void save_orderbooktx(uint64_t nxt64bits,uint64_t baseid,uint64_t relid,struct orderbook_tx *tx)
{
    char NXTaddr[64];
    uint64_t obookid;
    struct NXT_acct *np;
    struct rambook_info *rb;
    int32_t createdflag,maxallowed;
    obookid = _obookid(baseid,relid);
    maxallowed = calc_users_maxopentrades(nxt64bits);
    expand_nxt64bits(NXTaddr,nxt64bits);
    rb = get_rambook(baseid,relid);
    np = get_NXTacct(&createdflag,Global_mp,NXTaddr);
    if ( np->openorders >= maxallowed )
        purge_oldest_order(rb,tx); // allow one pair per orderbook
    add_user_order(rb,&tx->iQ);
    np->openorders++;
}

void flip_iQ(struct InstantDEX_quote *iQ)
{
    uint64_t amount;
    iQ->type ^= (_ASKMASK | _FLIPMASK);
    amount = iQ->baseamount;
    iQ->baseamount = iQ->relamount;
    iQ->relamount = amount;
}

double calc_price_volume(double *volumep,uint64_t baseamount,uint64_t relamount)
{
    *volumep = ((double)baseamount / SATOSHIDEN);
    return((double)relamount / baseamount);
}

void set_best_amounts(uint64_t *baseamountp,uint64_t *relamountp,double price,double volume)
{
    double checkprice,checkvol,distA,distB,metric,bestmetric = (1. / SMALLVAL);
    uint64_t baseamount,relamount,bestbaseamount = 0,bestrelamount = 0;
    int32_t i,j;
    baseamount = volume * SATOSHIDEN;
    relamount = (price * baseamount);
    for (i=-1; i<=1; i++)
        for (j=-1; j<=1; j++)
        {
            checkprice = calc_price_volume(&checkvol,baseamount+i,relamount+j);
            distA = (checkprice - price);
            distA *= distA;
            distB = (checkvol - volume);
            distB *= distB;
            metric = sqrt(distA + distB);
            if ( metric < bestmetric )
            {
                bestmetric = metric;
                bestbaseamount = baseamount + i;
                bestrelamount = relamount + j;
                //printf("i.%d j.%d metric. %f\n",i,j,metric);
            }
        }
    *baseamountp = bestbaseamount;
    *relamountp = bestrelamount;
}

int32_t create_orderbook_tx(int32_t polarity,struct orderbook_tx *tx,int32_t type,uint64_t nxt64bits,uint64_t baseid,uint64_t relid,double price,double volume,uint64_t baseamount,uint64_t relamount)
{
    if ( baseamount == 0 && relamount == 0 )
        set_best_amounts(&baseamount,&relamount,price,volume);
    memset(tx,0,sizeof(*tx));
    tx->iQ.timestamp = (uint32_t)time(NULL);
    tx->iQ.type = type;
    tx->iQ.nxt64bits = nxt64bits;
    if ( baseid > relid )
    {
        tx->iQ.type |= _FLIPMASK;
        tx->baseid = relid;
        tx->relid = baseid;
        tx->iQ.baseamount = relamount;
        tx->iQ.relamount = baseamount;
        //polarity *= -1;
    }
    else
    {
        tx->baseid = baseid;
        tx->relid = relid;
        tx->iQ.baseamount = baseamount;
        tx->iQ.relamount = relamount;
    }
    if ( polarity < 0 )
        tx->iQ.type |= _ASKMASK;
    return(0);
}

void free_orderbook(struct orderbook *op)
{
    if ( op != 0 )
    {
        if ( op->bids != 0 )
            free(op->bids);
        if ( op->asks != 0 )
            free(op->asks);
        free(op);
    }
}

void set_baserel_flipped(uint64_t *baseidp,uint64_t *baseamountp,uint64_t *relidp,uint64_t *relamountp,struct InstantDEX_quote *iQ,uint64_t refbaseid,uint64_t refrelid)
{
    if ( _iQ_flipped(iQ) == 0 )
    {
        *baseidp = refbaseid, *baseamountp = iQ->baseamount;
        *relidp = refrelid, *relamountp = iQ->relamount;
    }
    else
    {
        *baseidp = refrelid, *baseamountp = iQ->relamount;
        *relidp = refbaseid, *relamountp = iQ->baseamount;
    }
}

cJSON *gen_orderbook_item(struct InstantDEX_quote *iQ,int32_t allflag,uint64_t refbaseid,uint64_t refrelid)
{
    char NXTaddr[64],numstr[64];
    cJSON *array = 0;
    double price,volume;
    uint64_t baseid,relid,baseamount,relamount;
    if ( iQ != 0 )
    {
        set_baserel_flipped(&baseid,&baseamount,&relid,&relamount,iQ,refbaseid,refrelid);
        if ( baseamount != 0 && relamount != 0 )
        {
            price = calc_price_volume(&volume,baseamount,relamount);
            array = cJSON_CreateArray();
            sprintf(numstr,"%.11f",price), cJSON_AddItemToArray(array,cJSON_CreateString(numstr));
            sprintf(numstr,"%.8f",volume),cJSON_AddItemToArray(array,cJSON_CreateString(numstr));
            if ( allflag != 0 )
            {
                cJSON_AddItemToArray(array,cJSON_CreateNumber(iQ->type & _TYPEMASK));
                expand_nxt64bits(NXTaddr,iQ->nxt64bits);
                cJSON_AddItemToArray(array,cJSON_CreateString(NXTaddr));
            }
        }
    }
    return(array);
}

cJSON *gen_InstantDEX_json(struct InstantDEX_quote *iQ,uint64_t refbaseid,uint64_t refrelid)
{
    cJSON *json = cJSON_CreateObject();
    char numstr[64],base[64],rel[64];
    double price,volume;
    uint64_t baseid,baseamount,relid,relamount;
    set_baserel_flipped(&baseid,&baseamount,&relid,&relamount,iQ,refbaseid,refrelid);
    price = calc_price_volume(&volume,baseamount,relamount);
    cJSON_AddItemToObject(json,"requestType",cJSON_CreateString((_iQ_dir(iQ) > 0) ? "bid" : "ask"));
    set_assetname(base,baseid), cJSON_AddItemToObject(json,"base",cJSON_CreateString(base));
    set_assetname(rel,relid), cJSON_AddItemToObject(json,"rel",cJSON_CreateString(rel));
    cJSON_AddItemToObject(json,"price",cJSON_CreateNumber(price));
    cJSON_AddItemToObject(json,"volume",cJSON_CreateNumber(volume));
    cJSON_AddItemToObject(json,"timestamp",cJSON_CreateNumber(iQ->timestamp));
    cJSON_AddItemToObject(json,"age",cJSON_CreateNumber((uint32_t)time(NULL) - iQ->timestamp));
    cJSON_AddItemToObject(json,"type",cJSON_CreateNumber(iQ->type));
    sprintf(numstr,"%llu",(long long)iQ->nxt64bits), cJSON_AddItemToObject(json,"NXT",cJSON_CreateString(numstr));
    
    sprintf(numstr,"%llu",(long long)baseid), cJSON_AddItemToObject(json,"baseid",cJSON_CreateString(numstr));
    sprintf(numstr,"%llu",(long long)baseamount), cJSON_AddItemToObject(json,"baseamount",cJSON_CreateString(numstr));
    sprintf(numstr,"%llu",(long long)relid), cJSON_AddItemToObject(json,"relid",cJSON_CreateString(numstr));
    sprintf(numstr,"%llu",(long long)relamount), cJSON_AddItemToObject(json,"relamount",cJSON_CreateString(numstr));
    return(json);
}

/*double parse_InstantDEX_json(uint64_t *baseidp,uint64_t *relidp,struct InstantDEX_quote *iQ,cJSON *json)
{
    char basestr[MAX_JSON_FIELD],relstr[MAX_JSON_FIELD],nxtstr[MAX_JSON_FIELD],cmd[MAX_JSON_FIELD];
    struct orderbook_tx T;
    uint64_t nxt64bits,baseamount,relamount;
    double price,volume;
    int32_t polarity;
    uint32_t type;
    //({"requestType":"[bid|ask]","type":0,"NXT":"13434315136155299987","base":"4551058913252105307","srcvol":"1.01000000","rel":"11060861818140490423","destvol":"0.00606000"}) 0x7f24700111c0
    *baseidp = *relidp = 0;
    memset(iQ,0,sizeof(*iQ));
    if ( json != 0 )
    {
        copy_cJSON(basestr,cJSON_GetObjectItem(json,"base")), *baseidp = calc_nxt64bits(basestr);
        copy_cJSON(relstr,cJSON_GetObjectItem(json,"rel")), *relidp = calc_nxt64bits(relstr);
        copy_cJSON(basestr,cJSON_GetObjectItem(json,"baseamount")), baseamount = calc_nxt64bits(basestr);
        copy_cJSON(relstr,cJSON_GetObjectItem(json,"relamount")), relamount = calc_nxt64bits(relstr);
        copy_cJSON(cmd,cJSON_GetObjectItem(json,"requestType"));
        type = (uint32_t)get_API_int(cJSON_GetObjectItem(json,"type"),0);
        if ( strcmp(cmd,"ask") == 0 )
        {
            polarity = -1;
            type |= _ASKMASK;
        } else polarity = 1;
        if ( *baseidp != 0 && *relidp != 0 )
        {
            if ( relamount != 0 && baseamount != 0 )
            {
                price = calc_price_volume(&volume,baseamount,relamount);
                copy_cJSON(nxtstr,cJSON_GetObjectItem(json,"NXT")), nxt64bits = calc_nxt64bits(nxtstr);
                printf("conv_InstantDEX_json: obookid.%llu base %.8f -> rel %.8f price %f vol %f\n",(long long)(*baseidp ^ *relidp),dstr(baseamount),dstr(relamount),price,volume);
                create_orderbook_tx(polarity,&T,type,nxt64bits,*baseidp,*relidp,price,volume,0,0);
                T.iQ.timestamp = (uint32_t)get_API_int(cJSON_GetObjectItem(json,"timestamp"),0);
                *iQ = T.iQ;
            }
        }
    }
    return(_iQ_price(iQ));
}*/

int _decreasing_quotes(const void *a,const void *b)
{
#define iQ_a ((struct InstantDEX_quote *)a)
#define iQ_b ((struct InstantDEX_quote *)b)
    double vala,valb;
    vala = _iQ_price(iQ_a);
    valb = _iQ_price(iQ_b);
	if ( valb > vala )
		return(1);
	else if ( valb < vala )
		return(-1);
	return(0);
#undef iQ_a
#undef iQ_b
}

int _increasing_quotes(const void *a,const void *b)
{
#define iQ_a ((struct InstantDEX_quote *)a)
#define iQ_b ((struct InstantDEX_quote *)b)
    double vala,valb;
    vala = _iQ_price(iQ_a);
    valb = _iQ_price(iQ_b);
	if ( valb > vala )
		return(-1);
	else if ( valb < vala )
		return(1);
	return(0);
#undef iQ_a
#undef iQ_b
}

void update_orderbook(int32_t iter,struct orderbook *op,int32_t *numbidsp,int32_t *numasksp,struct InstantDEX_quote *iQ)
{
    if ( iter == 0 )
    {
        if ( _iQ_dir(iQ) > 0 )
            op->numbids++;
        else op->numasks++;
    }
    else
    {
        if ( _iQ_dir(iQ) > 0 )
            op->bids[(*numbidsp)++] = *iQ;
        else op->asks[(*numasksp)++] = *iQ;
    }
}

// combine all orderbooks with flags, maybe even arbitrage, so need cloud quotes

void add_to_orderbook(struct orderbook *op,int32_t iter,int32_t *numbidsp,int32_t *numasksp,struct orderbook_tx *order,int32_t refflipped,int32_t oldest)
{
    int32_t flipped;
    if ( order->baseid < order->relid ) flipped = 0;
    else flipped = _FLIPMASK;
    if ( (flipped != refflipped && (order->iQ.type & _FLIPMASK) == refflipped) || (flipped == refflipped && (order->iQ.type & _FLIPMASK) != refflipped) )
        flip_iQ(&order->iQ);
    //if ( (order->iQ.type & _FLIPMASK) != refflipped )
    //    flip_iQ(&order->iQ);
    if ( order->iQ.timestamp >= oldest )
        update_orderbook(iter,op,numbidsp,numasksp,&order->iQ);
}

struct orderbook *create_orderbook(uint32_t oldest,uint64_t refbaseid,uint64_t refrelid,struct orderbook_tx **feedorders,int32_t numfeeds)
{
    struct orderbook_tx T;
    struct InstantDEX_quote *quotes = 0;
    uint32_t purgetime = ((uint32_t)time(NULL) - NODESTATS_EXPIRATION);
    int32_t i,iter,numbids,numasks,refflipped,numquotes = 0;
    size_t retdlen = 0;
    char obookstr[64];
    struct orderbook *op = 0;
    void *retdata,*p;
    DBT *origdata,*data = 0;
    expand_nxt64bits(obookstr,refbaseid ^ refrelid);
    op = (struct orderbook *)calloc(1,sizeof(*op));
    op->baseid = refbaseid;
    op->relid = refrelid;
    if ( refbaseid < refrelid ) refflipped = 0;
    else refflipped = _FLIPMASK;
    origdata = 0;//(DBT *)find_storage(INSTANTDEX_DATA,obookstr,65536);
    for (iter=0; iter<2; iter++)
    {
        numbids = numasks = 0;
        if ( numfeeds > 0 && feedorders != 0 )
        {
            for (i=0; i<numfeeds; i++)
                add_to_orderbook(op,iter,&numbids,&numasks,feedorders[i],refflipped,oldest);
        }
        if ( quotes != 0 || (quotes= get_matching_quotes(&numquotes,refbaseid,refrelid)) != 0 )
        {
            for (i=0; i<numquotes; i++)
            {
                memset(&T,0,sizeof(T));
                T.baseid = refbaseid;
                T.relid = refrelid;
                T.iQ = quotes[i];
                add_to_orderbook(op,iter,&numbids,&numasks,&T,refflipped,oldest);
            }
        }
        if ( (data= origdata) != 0 )
        {
            for (DB_MULTIPLE_INIT(p,data); ;)
            {
                DB_MULTIPLE_NEXT(p,data,retdata,retdlen);
                if ( p == NULL )
                    break;
                T.iQ = *(struct InstantDEX_quote *)retdata;
                if ( (T.iQ.type & _FLIPMASK) != refflipped )
                    flip_iQ(&T.iQ);
                T.baseid = refbaseid;
                T.relid = refrelid;
                if ( iter == 0 )
                {
                    for (i=0; i<retdlen; i++)
                        printf("%02x ",((uint8_t *)retdata)[i]);
                    printf("%p %p: %d\n",p,retdata,(int)retdlen);
                    printf("Q: %llu -> %llu NXT.%llu %u type.%d\n",(long long)T.iQ.baseamount,(long long)T.iQ.relamount,(long long)T.iQ.nxt64bits,T.iQ.timestamp,T.iQ.type);
                }
                if ( T.iQ.timestamp >= oldest )
                    update_orderbook(iter,op,&numbids,&numasks,&T.iQ);
                else if ( T.iQ.timestamp < purgetime )
                {
                    
                }
            }
        }
        if ( iter == 0 )
        {
            if ( op->numbids > 0 )
                op->bids = (struct InstantDEX_quote *)calloc(op->numbids,sizeof(*op->bids));
            if ( op->numasks > 0 )
                op->asks = (struct InstantDEX_quote *)calloc(op->numasks,sizeof(*op->asks));
        }
        else
        {
            if ( op->numbids > 0 || op->numasks > 0 )
            {
                if ( op->numbids > 0 )
                    qsort(op->bids,op->numbids,sizeof(*op->bids),_decreasing_quotes);
                if ( op->numasks > 0 )
                    qsort(op->asks,op->numasks,sizeof(*op->asks),_increasing_quotes);
            }
            else free(op), op = 0;
        }
    }
    //printf("(%f %f %llu %u)\n",quotes->price,quotes->vol,(long long)quotes->nxt64bits,quotes->timestamp);
    if ( origdata != 0 )
    {
        if ( origdata->data != 0 )
            free(origdata->data);
        free(origdata);
    }
    return(op);
}

char *orderbook_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    uint32_t oldest;
    int32_t i,allflag;
    uint64_t baseid,relid;
    cJSON *json,*bids,*asks,*item;
    struct orderbook *op;
    char obook[64],buf[MAX_JSON_FIELD],base[64],rel[64],baserel[128],datastr[MAX_JSON_FIELD],assetA[64],assetB[64],*retstr = 0;
    baseid = get_API_nxt64bits(objs[0]);
    relid = get_API_nxt64bits(objs[1]);
    allflag = get_API_int(objs[2],0);
    oldest = get_API_int(objs[3],0);
    expand_nxt64bits(obook,baseid ^ relid);
    sprintf(buf,"{\"baseid\":\"%llu\",\"relid\":\"%llu\",\"oldest\":%u}",(long long)baseid,(long long)relid,oldest);
    init_hexbytes_noT(datastr,(uint8_t *)buf,strlen(buf));
    printf("ORDERBOOK.(%s)\n",buf);
    //if ( baseid != 0 && relid != 0 )
   //     if ( (retstr= kademlia_find("findvalue",previpaddr,NXTaddr,NXTACCTSECRET,sender,obook,datastr,0)) != 0 )
     //       free(retstr);
    retstr = 0;
    if ( baseid != 0 && relid != 0 && (op= create_orderbook(oldest,baseid,relid,0,0)) != 0 )
    {
        if ( op->numbids == 0 && op->numasks == 0 )
            retstr = clonestr("{\"error\":\"no bids or asks\"}");
        else
        {
            json = cJSON_CreateObject();
            bids = cJSON_CreateArray();
            for (i=0; i<op->numbids; i++)
            {
                if ( (item= gen_orderbook_item(&op->bids[i],allflag,op->baseid,op->relid)) != 0 )
                    cJSON_AddItemToArray(bids,item);
            }
            asks = cJSON_CreateArray();
            for (i=0; i<op->numasks; i++)
            {
                if ( (item= gen_orderbook_item(&op->asks[i],allflag,op->baseid,op->relid)) != 0 )
                    cJSON_AddItemToArray(asks,item);
            }
            expand_nxt64bits(assetA,op->baseid);
            expand_nxt64bits(assetB,op->relid);
            set_assetname(base,op->baseid);
            set_assetname(rel,op->relid);
            sprintf(baserel,"%s/%s",base,rel);
            cJSON_AddItemToObject(json,"pair",cJSON_CreateString(baserel));
            cJSON_AddItemToObject(json,"obookid",cJSON_CreateString(obook));
            cJSON_AddItemToObject(json,"baseid",cJSON_CreateString(assetA));
            cJSON_AddItemToObject(json,"relid",cJSON_CreateString(assetB));
            cJSON_AddItemToObject(json,"bids",bids);
            cJSON_AddItemToObject(json,"asks",asks);
            cJSON_AddItemToObject(json,"NXT",cJSON_CreateString(NXTaddr));
            retstr = cJSON_Print(json);
        }
        free_orderbook(op);
    }
    else
    {
        sprintf(buf,"{\"error\":\"no such orderbook.(%llu ^ %llu)\"}",(long long)baseid,(long long)relid);
        retstr = clonestr(buf);
    }
    return(retstr);
}

void submit_quote(char *quotestr)
{
    //uint64_t call_SuperNET_broadcast(struct pserver_info *pserver,char *msg,int32_t len,int32_t duration);
    int32_t len;
    char _tokbuf[4096];
    struct pserver_info *pserver;
    struct coin_info *cp = get_coin_info("BTCD");
    if ( cp != 0 )
    {
        printf("submit_quote.(%s)\n",quotestr);
        len = construct_tokenized_req(_tokbuf,quotestr,cp->srvNXTACCTSECRET);
        if ( get_top_MMaker(&pserver) == 0 )
            call_SuperNET_broadcast(pserver,_tokbuf,len,300);
        call_SuperNET_broadcast(0,_tokbuf,len,300);
    }
}

char *placequote_func(char *previpaddr,int32_t dir,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    cJSON *json;
    uint64_t baseamount,relamount,nxt64bits,baseid,relid,txid = 0;
    double price,volume;
    int32_t remoteflag,type;
    struct orderbook_tx tx,*txp;
    char buf[MAX_JSON_FIELD],txidstr[64],*jsonstr,*retstr = 0;
    remoteflag = (is_remote_access(previpaddr) != 0);
    nxt64bits = calc_nxt64bits(sender);
    baseid = get_API_nxt64bits(objs[0]);
    relid = get_API_nxt64bits(objs[1]);
    if ( baseid == 0 || relid == 0 )
        return(clonestr("{\"error\":\"illegal asset id\"}"));
    baseamount = get_API_nxt64bits(objs[4]);
    relamount = get_API_nxt64bits(objs[5]);
    if ( baseamount != 0 && relamount != 0 )
        price = calc_price_volume(&volume,baseamount,relamount);
    else
    {
        volume = get_API_float(objs[2]);
        price = get_API_float(objs[3]);
    }
    type = (int32_t)get_API_int(objs[6],0);
    printf("placequote type.%d dir.%d sender.(%s) valid.%d price %.11f vol %.8f\n",type,dir,sender,valid,price,volume);
    if ( sender[0] != 0 && valid > 0 )
    {
        if ( price != 0. && volume != 0. && dir != 0 )
        {
            create_orderbook_tx(dir,&tx,0,nxt64bits,baseid,relid,price,volume,baseamount,relamount);
            save_orderbooktx(nxt64bits,baseid,relid,&tx);
            if ( _iQ_flipped(&tx.iQ) != 0 )
                dir = -dir;
            if ( remoteflag == 0 && (json= gen_InstantDEX_json(&tx.iQ,baseid,relid)) != 0 )
            {
                jsonstr = cJSON_Print(json);
                stripwhite_ns(jsonstr,strlen(jsonstr));
                submit_quote(jsonstr);
                free_json(json);
                free(jsonstr);
            }
            txid = calc_txid((uint8_t *)&tx,sizeof(tx));
            if ( txid != 0 )
            {
                txp = calloc(1,sizeof(*txp));
                *txp = tx;
                expand_nxt64bits(txidstr,txid);
                sprintf(buf,"{\"result\":\"success\",\"txid\":\"%s\"}",txidstr);
                retstr = clonestr(buf);
                printf("placequote.(%s)\n",buf);
            }
        }
        if ( retstr == 0 )
        {
            sprintf(buf,"{\"error submitting\":\"place%s error %llu/%llu volume %f price %f\"}",dir>0?"bid":"ask",(long long)baseid,(long long)relid,volume,price);
            retstr = clonestr(buf);
        }
    }
    else
    {
        sprintf(buf,"{\"error\":\"place%s error %llu/%llu dir.%d volume %f price %f\"}",dir>0?"bid":"ask",(long long)baseid,(long long)relid,dir,volume,price);
        retstr = clonestr(buf);
    }
    return(retstr);
}

char *placebid_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    return(placequote_func(previpaddr,1,sender,valid,objs,numobjs,origargstr));
}

char *placeask_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    return(placequote_func(previpaddr,-1,sender,valid,objs,numobjs,origargstr));
}

char *bid_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    return(placequote_func(previpaddr,1,sender,valid,objs,numobjs,origargstr));
}

char *ask_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    return(placequote_func(previpaddr,-1,sender,valid,objs,numobjs,origargstr));
}

char *allorderbooks_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    cJSON *json;
    char *jsonstr;
    if ( (json= all_orderbooks()) != 0 )
    {
        jsonstr = cJSON_Print(json);
        free_json(json);
        return(jsonstr);
    }
    return(clonestr("{\"error\":\"no orderbooks\"}"));
}

char *openorders_func(char *NXTaddr,char *NXTACCTSECRET,char *previpaddr,char *sender,int32_t valid,cJSON **objs,int32_t numobjs,char *origargstr)
{
    cJSON *array,*json = 0;
    struct rambook_info **obooks,*rb;
    struct InstantDEX_quote *iQ;
    int32_t i,j,numbooks,n = 0;
    char nxtaddr[64],*jsonstr;
    if ( (obooks= get_allrambooks(&numbooks)) != 0 )
    {
        array = cJSON_CreateArray();
        for (i=0; i<numbooks; i++)
        {
            rb = obooks[i];
            if ( rb->numquotes == 0 )
                continue;
            for (j=0; j<rb->numquotes; j++)
            {
                iQ = &rb->quotes[j];
                expand_nxt64bits(nxtaddr,iQ->nxt64bits);
                if ( strcmp(NXTaddr,nxtaddr) == 0 )
                    cJSON_AddItemToArray(array,gen_InstantDEX_json(iQ,rb->baseid,rb->relid)), n++;
            }
        }
        free(obooks);
        if ( n > 0 )
        {
            json = cJSON_CreateObject();
            cJSON_AddItemToObject(json,"openorders",array);
            jsonstr = cJSON_Print(json);
            free_json(json);
            return(jsonstr);
        }
    }
    return(clonestr("{\"result\":\"no openorders\"}"));
}

int32_t filtered_orderbook(char *datastr,char *jsonstr)
{
    cJSON *json;
    uint64_t refbaseid,refrelid;
    struct orderbook_tx T;
    int32_t i,refflipped;
    uint32_t oldest;
    size_t retdlen = 0;
    char obookstr[64];
    void *retdata,*p;
    DBT *data = 0;
    datastr[0] = 0;
    if ( (json= cJSON_Parse(jsonstr)) == 0 )
        return(-1);
    refbaseid = get_API_nxt64bits(cJSON_GetObjectItem(json,"baseid"));
    refrelid = get_API_nxt64bits(cJSON_GetObjectItem(json,"rel"));
    oldest = get_API_int(cJSON_GetObjectItem(json,"oldest"),0);
    free_json(json);
    if ( refbaseid == 0 || refrelid == 0 )
        return(-2);
    expand_nxt64bits(obookstr,refbaseid ^ refrelid);
    if ( refbaseid < refrelid ) refflipped = 0;
    else refflipped = _FLIPMASK;
    data = (DBT *)find_storage(INSTANTDEX_DATA,obookstr,65536);
    if ( data != 0 )
    {
        init_hexbytes_noT(datastr,(uint8_t *)"{\"data\":\"",strlen("{\"data\":\""));
        for (DB_MULTIPLE_INIT(p,data); ;)
        {
            DB_MULTIPLE_NEXT(p,data,retdata,retdlen);
            if ( p == NULL )
                break;
            T.iQ = *(struct InstantDEX_quote *)retdata;
            if ( (T.iQ.type & _FLIPMASK) != refflipped )
                flip_iQ(&T.iQ);
            T.baseid = refbaseid;
            T.relid = refrelid;
            if ( T.iQ.timestamp >= oldest && retdlen == sizeof(T.iQ) )
            {
                for (i=0; i<retdlen; i++)
                    printf("%02x ",((uint8_t *)retdata)[i]);
                printf("%p %p: %d\n",p,retdata,(int)retdlen);
                printf("Q: %llu -> %llu NXT.%llu %u type.%d\n",(long long)T.iQ.baseamount,(long long)T.iQ.relamount,(long long)T.iQ.nxt64bits,T.iQ.timestamp,T.iQ.type);
                init_hexbytes_noT(datastr+strlen(datastr),retdata,retdlen);
            }
        }
    }
    if ( datastr[0] != 0 )
        init_hexbytes_noT(datastr+strlen(datastr),(uint8_t *)"\"}",strlen("\"}"));
    return((int32_t)strlen(datastr));
}

/*void check_for_InstantDEX(char *decoded,char *keystr)
{
    cJSON *json;
    double price;
    uint64_t baseid,relid;
    int32_t ret,i,len;
    struct SuperNET_db *sdb = &SuperNET_dbs[INSTANTDEX_DATA];
    struct InstantDEX_quote Q,iQs[MAX_JSON_FIELD/sizeof(Q)];
    char checkstr[64],datastr[MAX_JSON_FIELD];
    json = cJSON_Parse(decoded);
    //({"requestType":"quote","type":0,"NXT":"13434315136155299987","base":"4551058913252105307","srcvol":"1.01000000","rel":"11060861818140490423","destvol":"0.00606000"}) 0x7f24700111c0
    if ( json != 0 )
    {
        if ( extract_cJSON_str(datastr,sizeof(datastr),json,"data") > 0 )
        {
            len = (int32_t)strlen(datastr)/2;
            len = decode_hex((uint8_t *)iQs,len,datastr);
            for (i=0; i<len; i+=sizeof(Q))
            {
                Q = iQs[i/sizeof(Q)];
                printf("%ld Q.(%s): %llu -> %llu NXT.%llu %u type.%d\n",i/sizeof(Q),keystr,(long long)Q.baseamount,(long long)Q.relamount,(long long)Q.nxt64bits,Q.timestamp,Q.type);
            }
        }
        else
        {
            price = parse_InstantDEX_json(&baseid,&relid,&Q,json);
            expand_nxt64bits(checkstr,baseid ^ relid);
            if ( price != 0. && relid != 0 && baseid != 0 && strcmp(checkstr,keystr) == 0 )
            {
                //int z;
                //for (z=0; z<24; z++)
                //    printf("%02x ",((uint8_t *)&Q)[z]);
                printf(">>>>>> Q.(%s): %llu -> %llu NXT.%llu %u type.%d | price %f\n",keystr,(long long)Q.baseamount,(long long)Q.relamount,(long long)Q.nxt64bits,Q.timestamp,Q.type,price);
                if ( (ret= dbreplace_iQ(INSTANTDEX_DATA,keystr,&Q)) != 0 )
                    sdb->storage->err(sdb->storage,ret,"Database replace failed.");
            }
        }
        free_json(json);
    }
}*/

#undef _ASKMASK
#undef _TYPEMASK
#undef _obookid
#undef _iQ_dir
#undef _iQ_type
#undef _iQ_price
#undef _iQ_volume

#endif
