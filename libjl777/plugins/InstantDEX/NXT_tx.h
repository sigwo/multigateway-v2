//
//  NXT_tx.h
//
//  Created by jl777 on 7/9/14.
//  Copyright (c) 2014 jl777. All rights reserved.
//

#ifndef xcode_NXT_tx_h
#define xcode_NXT_tx_h

#define MAX_TXPTRS 1024

union _NXT_tx_num { int64_t amountNQT; int64_t quantityQNT; };
struct NXT_tx
{
    bits256 refhash,sighash,fullhash;
    uint64_t senderbits,recipientbits,assetidbits,txid,priceNQT,quoteid;
    int64_t feeNQT;
    union _NXT_tx_num U;
    int32_t deadline,type,subtype,verify,number;
    uint32_t timestamp;
    char comment[4096];
};

uint32_t calc_expiration(struct NXT_tx *tx)
{
    if ( tx == 0 || tx->timestamp == 0 )
        return(0);
    return((NXT_GENESISTIME + tx->timestamp) + 60*tx->deadline);
}

void free_txptrs(struct NXT_tx *txptrs[],int32_t numptrs)
{
    int32_t i;
    if ( txptrs != 0 && numptrs > 0 )
    {
        for (i=0; i<numptrs; i++)
            if ( txptrs[i] != 0 )
                free(txptrs[i]);
    }
}

struct NXT_tx *search_txptrs(struct NXT_tx *txptrs[],uint64_t txid,uint64_t quoteid,uint64_t baseid,uint64_t relid)
{
    int32_t i; struct NXT_tx *tx;
    for (i=0; i<MAX_TXPTRS; i++)
    {
        if ( (tx= txptrs[i]) == 0 )
            return(0);
        if ( quoteid != 0 )
            printf("Q.%llu ",(long long)tx->quoteid);
        if ( (txid != 0 && tx->txid == txid) || (quoteid != 0 && tx->quoteid == quoteid) || (baseid != 0 && tx->assetidbits == baseid) || (relid != 0 && tx->assetidbits == relid) )
            return(tx);
    }
    return(0);
}

int32_t NXTutxcmp(struct NXT_tx *ref,struct NXT_tx *tx,double myshare)
{
    if ( ref->senderbits == tx->senderbits && ref->recipientbits == tx->recipientbits && ref->type == tx->type && ref->subtype == tx->subtype)
    {
        if ( ref->feeNQT != tx->feeNQT || ref->deadline != tx->deadline )
            return(-1);
        if ( ref->assetidbits != NXT_ASSETID )
        {
            if ( ref->assetidbits == tx->assetidbits && fabs((ref->U.quantityQNT*myshare) - tx->U.quantityQNT) < 0.5 && strcmp(ref->comment,tx->comment) == 0 )
                return(0);
        }
        else
        {
            if ( fabs((ref->U.amountNQT*myshare) - tx->U.amountNQT) < 0.5 )
                return(0);
        }
    }
    return(-1);
}

cJSON *gen_NXT_tx_json(struct NXT_tx *utx,char *reftxid,double myshare,char *NXTACCTSECRET,uint64_t nxt64bits)
{
    cJSON *json = 0;
    char cmd[MAX_JSON_FIELD],destNXTaddr[64],assetidstr[64],*retstr;
    if ( utx->senderbits == nxt64bits )
    {
        expand_nxt64bits(destNXTaddr,utx->recipientbits);
        cmd[0] = 0;
        if ( utx->type == 0 && utx->subtype == 0 )
            sprintf(cmd,"requestType=sendMoney&amountNQT=%lld",(long long)(utx->U.amountNQT*myshare));
        else
        {
            expand_nxt64bits(assetidstr,utx->assetidbits);
            if ( utx->type == 2 && utx->subtype == 1 )
                sprintf(cmd,"requestType=transferAsset&asset=%s&quantityQNT=%lld",assetidstr,(long long)(utx->U.quantityQNT*myshare));
            else if ( utx->type == 5 && utx->subtype == 3 )
                sprintf(cmd,"requestType=transferCurrency&currency=%s&units=%lld",assetidstr,(long long)(utx->U.quantityQNT*myshare));
            else
            {
                printf("unsupported type.%d subtype.%d\n",utx->type,utx->subtype);
                return(0);
            }
        }
        if ( utx->comment[0] != 0 )
            strcat(cmd,"&messageIsText=true&message="),strcat(cmd,utx->comment);
        if ( reftxid != 0 && reftxid[0] != 0 && cmd[0] != 0 )
            strcat(cmd,"&referencedTransactionFullHash="),strcat(cmd,reftxid);
        if ( cmd[0] != 0 )
        {
            sprintf(cmd+strlen(cmd),"&deadline=%u&feeNQT=%lld&secretPhrase=%s&recipient=%s&broadcast=false",utx->deadline,(long long)utx->feeNQT,NXTACCTSECRET,destNXTaddr);
            if ( reftxid != 0 && reftxid[0] != 0 )
                sprintf(cmd+strlen(cmd),"&referencedTransactionFullHash=%s",reftxid);
            //printf("generated cmd.(%s) reftxid.(%s)\n",cmd,reftxid);
            retstr = issue_NXTPOST(cmd);
            if ( retstr != 0 )
            {
                json = cJSON_Parse(retstr);
                //if ( json != 0 )
                //   printf("Parsed.(%s)\n",cJSON_Print(json));
                free(retstr);
            }
        }
    } else printf("cant gen_NXT_txjson when sender.%llu is not me.%llu\n",(long long)utx->senderbits,(long long)nxt64bits);
    return(json);
}

uint64_t set_NXTtx(uint64_t nxt64bits,struct NXT_tx *tx,uint64_t assetidbits,int64_t amount,uint64_t other64bits,int32_t feebits)
{
    char assetidstr[64]; int32_t decimals;
    uint64_t fee = 0;
    struct NXT_tx U;
    memset(&U,0,sizeof(U));
    U.senderbits = nxt64bits;
    U.recipientbits = other64bits;
    U.assetidbits = assetidbits;
    if ( feebits >= 0 )
    {
        fee = (amount >> feebits);
        if ( fee == 0 )
            fee = 1;
    }
    if ( assetidbits != NXT_ASSETID )
    {
        expand_nxt64bits(assetidstr,assetidbits);
        U.type = get_assettype(&decimals,assetidstr);
        //U.subtype = ap->subtype;
        U.U.quantityQNT = amount - fee;
    } else U.U.amountNQT = amount - fee;
    U.feeNQT = MIN_NQTFEE;
    U.deadline = INSTANTDEX_TRIGGERDEADLINE;
    printf("set_NXTtx(%llu -> %llu) %.8f of %llu\n",(long long)U.senderbits,(long long)U.recipientbits,dstr(amount),(long long)assetidbits);
    *tx = U;
    return(fee);
}

int32_t calc_raw_NXTtx(char *utxbytes,char *sighash,uint64_t assetidbits,int64_t amount,uint64_t other64bits,char *NXTACCTSECRET,uint64_t nxt64bits)
{
    int32_t retval = -1;
    struct NXT_tx U;
    cJSON *json;
    utxbytes[0] = sighash[0] = 0;
    set_NXTtx(nxt64bits,&U,assetidbits,amount,other64bits,-1);
    json = gen_NXT_tx_json(&U,0,1.,NXTACCTSECRET,nxt64bits);
    if ( json != 0 )
    {
        if ( extract_cJSON_str(utxbytes,MAX_JSON_FIELD,json,"transactionBytes") > 0 && extract_cJSON_str(sighash,1024,json,"signatureHash") > 0 )
        {
            retval = 0;
            printf("generated utx.(%s) sighash.(%s)\n",utxbytes,sighash);
        } else printf("missing tx or sighash.(%s)\n",cJSON_Print(json));
        free_json(json);
    } else printf("calc_raw_NXTtx error doing gen_NXT_tx_json\n");
    return(retval);
}

struct NXT_tx *set_NXT_tx(cJSON *json)
{
    long size;
    int32_t n = 0;
    uint64_t assetidbits,quantity,price;
    cJSON *attachmentobj;
    struct NXT_tx *utx = 0;
    char sender[MAX_JSON_FIELD],recipient[MAX_JSON_FIELD],deadline[MAX_JSON_FIELD],feeNQT[MAX_JSON_FIELD],amountNQT[MAX_JSON_FIELD],type[MAX_JSON_FIELD],subtype[MAX_JSON_FIELD],verify[MAX_JSON_FIELD],referencedTransaction[MAX_JSON_FIELD],quantityQNT[MAX_JSON_FIELD],priceNQT[MAX_JSON_FIELD],comment[MAX_JSON_FIELD],assetidstr[MAX_JSON_FIELD],sighash[MAX_JSON_FIELD],fullhash[MAX_JSON_FIELD],timestamp[MAX_JSON_FIELD],transaction[MAX_JSON_FIELD];
    if ( json == 0 )
        return(0);
    if ( extract_cJSON_str(sender,sizeof(sender),json,"sender") > 0 ) n++;
    if ( extract_cJSON_str(recipient,sizeof(recipient),json,"recipient") > 0 ) n++;
    if ( extract_cJSON_str(referencedTransaction,sizeof(referencedTransaction),json,"referencedTransactionFullHash") > 0 ) n++;
    if ( extract_cJSON_str(amountNQT,sizeof(amountNQT),json,"amountNQT") > 0 ) n++;
    if ( extract_cJSON_str(feeNQT,sizeof(feeNQT),json,"feeNQT") > 0 ) n++;
    if ( extract_cJSON_str(deadline,sizeof(deadline),json,"deadline") > 0 ) n++;
    if ( extract_cJSON_str(type,sizeof(type),json,"type") > 0 ) n++;
    if ( extract_cJSON_str(subtype,sizeof(subtype),json,"subtype") > 0 ) n++;
    if ( extract_cJSON_str(verify,sizeof(verify),json,"verify") > 0 ) n++;
    if ( extract_cJSON_str(sighash,sizeof(sighash),json,"signatureHash") > 0 ) n++;
    if ( extract_cJSON_str(fullhash,sizeof(fullhash),json,"fullHash") > 0 ) n++;
    if ( extract_cJSON_str(timestamp,sizeof(timestamp),json,"timestamp") > 0 ) n++;
    if ( extract_cJSON_str(transaction,sizeof(transaction),json,"transaction") > 0 ) n++;
    comment[0] = 0;
    assetidbits = NXT_ASSETID;
    quantity = price = 0;
    size = sizeof(*utx);
    //if ( strcmp(type,"2") == 0 || strcmp(type,"5") == 0 )//&& strcmp(subtype,"3") == 0) )
    {
        attachmentobj = cJSON_GetObjectItem(json,"attachment");
        if ( attachmentobj != 0 )
        {
            if ( extract_cJSON_str(assetidstr,sizeof(assetidstr),attachmentobj,"asset") > 0 )
                assetidbits = calc_nxt64bits(assetidstr);
            else if ( extract_cJSON_str(assetidstr,sizeof(assetidstr),attachmentobj,"currency") > 0 )
                assetidbits = calc_nxt64bits(assetidstr);
            if ( extract_cJSON_str(comment,sizeof(comment),attachmentobj,"message") > 0 )
                size += strlen(comment);
            if ( extract_cJSON_str(quantityQNT,sizeof(quantityQNT),attachmentobj,"quantityQNT") > 0 )
                quantity = calc_nxt64bits(quantityQNT);
            else if ( extract_cJSON_str(quantityQNT,sizeof(quantityQNT),attachmentobj,"units") > 0 )
                quantity = calc_nxt64bits(quantityQNT);
            if ( extract_cJSON_str(priceNQT,sizeof(priceNQT),attachmentobj,"priceNQT") > 0 )
                price = calc_nxt64bits(priceNQT);
        }
    }
    utx = malloc(size);
    memset(utx,0,size);
    if ( strlen(referencedTransaction) == 64 )
        decode_hex(utx->refhash.bytes,32,referencedTransaction);
    if ( strlen(fullhash) == 64 )
        decode_hex(utx->fullhash.bytes,32,fullhash);
    if ( strlen(sighash) == 64 )
        decode_hex(utx->sighash.bytes,32,sighash);
    utx->txid = calc_nxt64bits(transaction);
    utx->senderbits = calc_nxt64bits(sender);
    utx->recipientbits = calc_nxt64bits(recipient);
    utx->assetidbits = assetidbits;
    utx->feeNQT = calc_nxt64bits(feeNQT);
    if ( quantity != 0 )
        utx->U.quantityQNT = quantity;
    else utx->U.amountNQT = calc_nxt64bits(amountNQT);
    utx->priceNQT = price;
    utx->deadline = atoi(deadline);
    utx->type = atoi(type);
    utx->subtype = atoi(subtype);
    utx->timestamp = atoi(timestamp);
    utx->verify = (strcmp("true",verify) == 0);
    strcpy(utx->comment,comment);
    unstringify(utx->comment);
    return(utx);
}

struct NXT_tx *sign_NXT_tx(char utxbytes[MAX_JSON_FIELD],char signedtx[MAX_JSON_FIELD],char *NXTACCTSECRET,uint64_t nxt64bits,struct NXT_tx *utx,char *reftxid,double myshare)
{
    cJSON *refjson,*txjson;
    char *parsed,*str,errstr[MAX_JSON_FIELD],_utxbytes[MAX_JSON_FIELD];
    struct NXT_tx *refutx = 0;
    printf("sign_NXT_tx.%llu  reftxid.(%s)\n",(long long)nxt64bits,reftxid);
    txjson = gen_NXT_tx_json(utx,reftxid,myshare,NXTACCTSECRET,nxt64bits);
    if ( utxbytes == 0 )
        utxbytes = _utxbytes;
    signedtx[0] = 0;
    if ( txjson != 0 )
    {
        if ( extract_cJSON_str(errstr,sizeof(errstr),txjson,"errorCode") > 0 )
        {
            str = cJSON_Print(txjson);
            strcpy(signedtx,str);
            strcpy(utxbytes,errstr);
            free(str);
        }
        else if ( extract_cJSON_str(utxbytes,MAX_JSON_FIELD,txjson,"unsignedTransactionBytes") > 0 && extract_cJSON_str(signedtx,MAX_JSON_FIELD,txjson,"transactionBytes") > 0 )
        {
            printf("signedbytes.(%s)\n",signedtx);
            if ( (parsed= issue_parseTransaction(signedtx)) != 0 )
            {
                refjson = cJSON_Parse(parsed);
                if ( refjson != 0 )
                {
                    refutx = set_NXT_tx(refjson);
                    free_json(refjson);
                }
                free(parsed);
            }
        }
        free_json(txjson);
    }
    return(refutx);
}

int32_t equiv_NXT_tx(struct NXT_tx *tx,char *comment)
{
    cJSON *json;
    uint64_t assetA,assetB,qtyA,qtyB,asset,qty;
    if ( (json= cJSON_Parse(comment)) != 0 )
    {
        assetA = get_satoshi_obj(json,"assetA");
        qtyA = get_satoshi_obj(json,"qtyA");
        assetB = get_satoshi_obj(json,"assetB");
        qtyB = get_satoshi_obj(json,"qtyB");
        free_json(json);
        if ( assetA != 0 && qtyA != 0 )
        {
            asset = assetA;
            qty = qtyA;
        }
        else if ( assetB != 0 && qtyB != 0 )
        {
            asset = assetB;
            qty = qtyB;
        } else return(-2);
        printf("tx->assetbits %llu vs asset.%llu\n",(long long)tx->assetidbits,(long long)asset);
        if ( tx->assetidbits != asset )
            return(-3);
        if ( tx->U.quantityQNT != qty ) // tx->quantityQNT is union as long as same assetid, then these can be compared directly
            return(-4);
        printf("tx->U.quantityQNT %llu vs qty.%llu\n",(long long)tx->U.quantityQNT,(long long)qty);
        return(0);
    }
    printf("error parsing.(%s)\n",comment);
    return(-1);
}

struct NXT_tx *conv_txbytes(char *txbytes)
{
    struct NXT_tx *tx = 0;
    char *parsed;
    cJSON *json;
    if ( (parsed = issue_parseTransaction(txbytes)) != 0 )
    {
        if ( (json= cJSON_Parse(parsed)) != 0 )
        {
            tx = set_NXT_tx(json);
            free_json(json);
        }
        free(parsed);
    }
    return(tx);
}

uint32_t get_txhashes(char *sighash,char *fullhash,struct NXT_tx *tx)
{
    init_hexbytes_noT(sighash,tx->sighash.bytes,sizeof(tx->sighash));
    init_hexbytes_noT(fullhash,tx->fullhash.bytes,sizeof(tx->fullhash));
    return(calc_expiration(tx));
}

uint64_t submit_triggered_nxtae(char **retjsonstrp,int32_t is_MS,char *bidask,uint64_t nxt64bits,char *NXTACCTSECRET,uint64_t assetid,uint64_t qty,uint64_t NXTprice,char *triggerhash,char *comment,uint64_t otherNXT,uint32_t triggerheight)
{
    int32_t deadline = 1 + time_to_nextblock(2)/60;
    uint64_t txid = 0;
    char cmd[4096],errstr[MAX_JSON_FIELD],*jsonstr;
    cJSON *json;
    if ( retjsonstrp != 0 )
        *retjsonstrp = 0;
    if ( triggerheight != 0 )
        deadline = DEFAULT_NXT_DEADLINE;
    sprintf(cmd,"requestType=%s&secretPhrase=%s&feeNQT=%llu&deadline=%d",bidask,NXTACCTSECRET,(long long)MIN_NQTFEE,deadline);
    sprintf(cmd+strlen(cmd),"&%s=%llu&%s=%llu",is_MS!=0?"units":"quantityQNT",(long long)qty,is_MS!=0?"currency":"asset",(long long)assetid);
    if ( NXTprice != 0 )
    {
        if ( is_MS != 0 )
            sprintf(cmd+strlen(cmd),"&rateNQT=%llu",(long long)NXTprice);
        else sprintf(cmd+strlen(cmd),"&priceNQT=%llu",(long long)NXTprice);
    }
    if ( otherNXT != 0 )
        sprintf(cmd+strlen(cmd),"&recipient=%llu",(long long)otherNXT);
    if ( triggerhash != 0 && triggerhash[0] != 0 )
    {
        if ( triggerheight == 0 )
            sprintf(cmd+strlen(cmd),"&referencedTransactionFullHash=%s",triggerhash);
        else sprintf(cmd+strlen(cmd),"&referencedTransactionFullHash=%s&phased=true&phasingFinishHeight=%u&phasingVotingModel=4&phasingQuorum=1&phasingLinkedFullHash=%s",triggerhash,triggerheight,triggerhash);
    }
    if ( comment != 0 && comment[0] != 0 )
        sprintf(cmd+strlen(cmd),"&message=%s",comment);
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        _stripwhite(jsonstr,' ');
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            copy_cJSON(errstr,cJSON_GetObjectItem(json,"error"));
            if ( errstr[0] == 0 )
                copy_cJSON(errstr,cJSON_GetObjectItem(json,"errorDescription"));
            if ( errstr[0] != 0 )
            {
                printf("submit_triggered_bidask.(%s) -> (%s)\n",cmd,jsonstr);
                if ( retjsonstrp != 0 )
                    *retjsonstrp = clonestr(errstr);
            }
            else txid = get_API_nxt64bits(cJSON_GetObjectItem(json,"transaction"));
        }
        free(jsonstr);
    }
    return(txid);
}

uint64_t send_feetx(uint64_t assetbits,uint64_t fee,char *fullhash,char *comment)
{
    char feeutx[MAX_JSON_FIELD],signedfeetx[MAX_JSON_FIELD];
    struct NXT_tx feeT,*feetx;
    uint64_t feetxid = 0;
    int32_t errcode;
    set_NXTtx(calc_nxt64bits(SUPERNET.NXTADDR),&feeT,assetbits,fee,calc_nxt64bits(INSTANTDEX_ACCT),-1);
    if ( comment != 0 && comment[0] != 0 )
        strcpy(feeT.comment,comment);
    printf("feetx for %llu %.8f fullhash.(%s) secret.(%s)\n",(long long)SUPERNET.NXTADDR,dstr(fee),fullhash,SUPERNET.NXTACCTSECRET);
    if ( (feetx= sign_NXT_tx(feeutx,signedfeetx,SUPERNET.NXTACCTSECRET,calc_nxt64bits(SUPERNET.NXTADDR),&feeT,fullhash,1.)) != 0 )
    {
        printf("broadcast fee for %llu\n",(long long)assetbits);
        feetxid = issue_broadcastTransaction(&errcode,0,signedfeetx,SUPERNET.NXTACCTSECRET);
        free(feetx);
    }
    return(feetxid);
}

int32_t NXT_set_revassettrade(uint64_t assetidbits,uint32_t ind,struct extra_info *extra)
{
    uint64_t revkey[2]; void *obj;
    if ( (obj= sp_object(DB_NXTtxids->db)) != 0 )
    {
        revkey[0] = assetidbits, revkey[1] = ind;
        //printf("set ind.%d <- txid.%llu\n",ind,(long long)extra->txidbits);
        if ( sp_set(obj,"key",revkey,sizeof(revkey)) == 0 && sp_set(obj,"value",extra,sizeof(*extra)) == 0 )
            return(sp_set(DB_NXTtxids->db,obj));
        else
        {
            sp_destroy(obj);
            printf("error NXT_set_revassettrade rev %llu ind.%d\n",(long long)extra->txidbits,ind);
        }
    }
    return(-1);
}

int32_t NXT_revassettrade(struct extra_info *extra,uint64_t assetidbits,uint32_t ind)
{
    void *obj,*result,*value; uint64_t revkey[2]; int32_t len = 0;
    memset(extra,0,sizeof(*extra));
    if ( (obj= sp_object(DB_NXTtxids->db)) != 0 )
    {
        revkey[0] = assetidbits, revkey[1] = ind;
        if ( sp_set(obj,"key",revkey,sizeof(revkey)) == 0 && (result= sp_get(DB_NXTtxids->db,obj)) != 0 )
        {
            value = sp_get(result,"value",&len);
            if ( len == sizeof(*extra) )
                memcpy(extra,value,len);
            else printf("NXT_revassettrade mismatched len.%d vs %ld\n",len,sizeof(*extra));
            sp_destroy(result);
        } //else sp_destroy(obj);
    }
    return(len);
}

int32_t NXT_add_assettrade(uint64_t assetidbits,uint64_t txidbits,void *value,int32_t valuelen,uint32_t ind,struct extra_info *extra)
{
    void *obj;
    if ( value != 0 )
    {
        if ( (obj= sp_object(DB_NXTtxids->db)) != 0 )
        {
            extra->assetidbits = assetidbits, extra->txidbits = txidbits, extra->ind = ind;
            if ( sp_set(obj,"key",&txidbits,sizeof(txidbits)) == 0 && sp_set(obj,"value",value,valuelen) == 0 )
                sp_set(DB_NXTtxids->db,obj);
            else
            {
                sp_destroy(obj);
                printf("error NXT_add_assettrade %llu ind.%d\n",(long long)txidbits,ind);
            }
        }
        NXT_set_revassettrade(assetidbits,ind,extra);
    }
    return(0);
}

char *NXT_assettrade(uint64_t assettxid)
{
    void *obj,*result,*value; int32_t len; char *retstr = 0;
    if ( (obj= sp_object(DB_NXTtxids->db)) != 0 )
    {
        if ( sp_set(obj,"key",&assettxid,sizeof(assettxid)) == 0 && (result= sp_get(DB_NXTtxids->db,obj)) != 0 )
        {
            value = sp_get(result,"value",&len);
            retstr = clonestr(value);
            sp_destroy(result);
        }// else sp_destroy(obj);
    }
    return(retstr);
}

char *NXT_tradestr(struct mgw777 *mgw,char *txid,int32_t writeflag,uint32_t ind)
{
    void *obj,*value,*result = 0; int32_t slen,len,flag; uint64_t txidbits; struct extra_info extra; char *txidjsonstr = 0; cJSON *json;
    printf("NXT_tradestr.(%s) write.%d ind.%d\n",txid,writeflag,ind);
    if ( txid[0] != 0 && (txidjsonstr= _issue_getTransaction(txid)) != 0 )
    {
        flag = writeflag;
        if ( (json= cJSON_Parse(txidjsonstr)) != 0 )
        {
            free(txidjsonstr);
            cJSON_DeleteItemFromObject(json,"requestProcessingTime");
            cJSON_DeleteItemFromObject(json,"confirmations");
            cJSON_DeleteItemFromObject(json,"transactionIndex");
            txidjsonstr = cJSON_Print(json);
            free_json(json);
        } else printf("PARSE ERROR.(%s)\n",txidjsonstr);
        _stripwhite(txidjsonstr,' ');
        slen = (int32_t)strlen(txidjsonstr)+1;
        txidbits = calc_nxt64bits(txid);
        if ( (obj= sp_object(DB_NXTtxids->db)) != 0 )
        {
            if ( sp_set(obj,"key",&txidbits,sizeof(txidbits)) == 0 && (result= sp_get(DB_NXTtxids->db,obj)) != 0 )
            {
                value = sp_get(result,"value",&len);
                if ( value != 0 )
                {
                    if ( len != slen || strcmp(value,txidjsonstr) != 0 )
                        printf("mismatched NXT_tradestr ind.%d for %llu: lens %d vs %d (%s) vs (%s)\n",ind,(long long)txidbits,slen,len,txidjsonstr,value);
                    else flag = 0;
                }
                sp_destroy(result);
            } //else sp_destroy(obj);
        }
        if ( flag != 0 )
        {
            int32_t mgw_markunspent(char *txidstr,int32_t vout,int32_t status);
            NXT_revassettrade(&extra,mgw->assetidbits,ind);
            /*savedbits = extra.txidbits;
            memset(&extra,0,sizeof(extra));
            if ( (txobj= cJSON_Parse(txidjsonstr)) != 0 )
            {
                extra.vout = process_assettransfer(&extra.height,&extra.senderbits,&extra.receiverbits,&extra.amount,&extra.flags,extra.coindata,0,mgw,txobj);
                free_json(txobj);
                if ( extra.vout >= 0 )
                {
                    mgw_markunspent(extra.coindata,extra.vout,MGW_DEPOSITDONE);
                    printf("MARK DEPOSITDONE %llu.%d oldval.%llu -> newval flags.%d %llu (%s v%d %.8f)\n",(long long)mgw->assetidbits,ind,(long long)savedbits,extra.flags,(long long)txidbits,extra.coindata,extra.vout,dstr(extra.amount));
                }
            } else extra.vout = -1;
            printf("for %llu.%d oldval.%llu -> newval flags.%d %llu (%s v%d %.8f)\n",(long long)mgw->assetidbits,ind,(long long)savedbits,extra.flags,(long long)txidbits,extra.coindata,extra.vout,dstr(extra.amount));*/
            NXT_add_assettrade(mgw->assetidbits,txidbits,txidjsonstr,slen,ind,&extra);
        }
    }
    return(txidjsonstr);
}

int32_t NXT_assettrades(struct mgw777 *mgw,uint64_t *txids,long max,int32_t firstindex,int32_t lastindex)
{
    char cmd[1024],txid[64],*jsonstr,*txidstr; cJSON *transfers,*array;
    int32_t i,n = 0; uint64_t txidbits,revkey[2];
    sprintf(cmd,"requestType=getAssetTransfers&asset=%s",mgw->assetidstr);
    if ( firstindex >= 0 && lastindex >= firstindex )
        sprintf(cmd + strlen(cmd),"&firstIndex=%u&lastIndex=%u",firstindex,lastindex);
    revkey[0] = mgw->assetidbits;
    //printf("issue.(%s) max.%ld\n",cmd,max);
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        //printf("(%s) -> (%s)\n",cmd,jsonstr);
        if ( (transfers = cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (array= cJSON_GetObjectItem(transfers,"transfers")) != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    copy_cJSON(txid,cJSON_GetObjectItem(cJSON_GetArrayItem(array,i),"assetTransfer"));
                    if ( txid[0] != 0 && (txidbits= calc_nxt64bits(txid)) != 0 )
                    {
                        if ( i < max )
                            txids[i] = txidbits;
                        if ( firstindex < 0 && lastindex <= firstindex )
                        {
                            if ( (txidstr= NXT_tradestr(mgw,txid,1,n - i)) != 0 )
                                free(txidstr);
                        }
                    }
                }
            } free_json(transfers);
        } free(jsonstr);
    }
    //if ( firstindex < 0 || lastindex <= firstindex )
    //    printf("assetid.(%s) -> %d entries\n",mgw->assetidstr,n);
    return(n);
}

int32_t update_NXT_assettrades(struct mgw777 *mgw)
{
    int32_t len,verifyflag = 0;
    uint64_t txids[100],mostrecent; int32_t i,count = 0; char txidstr[128],*txidjsonstr; struct extra_info extra;
    mgw->assetidbits = calc_nxt64bits(mgw->assetidstr);
    mgw->withdrawsum = mgw->numwithdraws = 0;
    if ( (len= NXT_revassettrade(&extra,mgw->assetidbits,0)) == sizeof(extra) )
    {
        //printf("got extra ind.%d\n",extra.ind);
        count = extra.ind;
        for (i=1; i<=count; i++)
        {
            NXT_revassettrade(&extra,mgw->assetidbits,i);
            /*if ( (extra.flags & MGW_PENDINGREDEEM) != 0 && (extra.flags & MGW_WITHDRAWDONE) == 0 )
            {
                int32_t mgw_update_redeem(struct mgw777 *mgw,struct extra_info *extra);
                expand_nxt64bits(nxt_txid,extra.txidbits);
                if ( in_jsonarray(mgw->limbo,nxt_txid) != 0 || mgw_update_redeem(mgw,&extra) != 0 )
                {
                    extra.flags |= MGW_WITHDRAWDONE;
                    NXT_set_revassettrade(mgw->assetidbits,i,&extra);
                }
            }*/
            //fprintf(stderr,"%llu.%d ",(long long)extra.txidbits,extra.flags);
        }
        //fprintf(stderr,"sequential tx.%d\n",count);
        NXT_revassettrade(&extra,mgw->assetidbits,count);
        mostrecent = extra.txidbits;
        //printf("mostrecent.%llu count.%d\n",(long long)mostrecent,count);
        for (i=0; i<sizeof(txids)/sizeof(*txids); i++)
        {
            if ( NXT_assettrades(mgw,&txids[i],1,i,i) == 1 && txids[i] == mostrecent )
            {
                if ( i != 0 )
                    printf("asset.(%s) count.%d i.%d mostrecent.%llu vs %llu\n",mgw->assetidstr,count,i,(long long)mostrecent,(long long)txids[i]);
                while ( i-- > 0 )
                {
                    expand_nxt64bits(txidstr,txids[i]);
                    if ( (txidjsonstr= NXT_tradestr(mgw,txidstr,1,++count)) != 0 )
                        free(txidjsonstr);
                }
                break;
            }
        }
        if ( i == 100 )
            count = 0;
    } else printf("cant get count len.%d\n",len);
    if ( count == 0 )
        count = NXT_assettrades(mgw,txids,sizeof(txids)/sizeof(*txids) - 1,-1,-1);
    if ( NXT_revassettrade(&extra,mgw->assetidbits,0) != sizeof(extra) || extra.ind != count )
    {
        memset(&extra,0,sizeof(extra));
        extra.ind = count;
        NXT_set_revassettrade(mgw->assetidbits,0,&extra);
    }
    if ( verifyflag != 0 )
        NXT_assettrades(mgw,txids,sizeof(txids)/sizeof(*txids) - 1,-1,-1);
    return(count);
}

#endif
