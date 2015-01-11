#ifndef LTC_SOURCE
  #define LTC_SOURCE
#endif // LTC_SOURCE

#ifndef DTFM_DESC
  #define DTFM_DESC
#endif // DTFM_DESC

#ifndef DUSE_TFM
  #define DUSE_TFM
#endif // DUSE_TFM



#include <stdint.h>
#include "base58.h"
#include <tomcrypt.h>
#include <tfm.h>
#include "btc_keyconv.h"
#include "tomcrypt_branch.h"

static void reverse_array(uint8_t *array, int n)
{
  int c, t, end;

  end = n - 1;

  for (c = 0; c < n/2; c++) {
    t          = array[c];
    array[c]   = array[end];
    array[end] = t;
    end--;
  }

}


//
// According to https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
//
static int pubkey_to_address(char *address,unsigned char *pubkey,int pubkey_len)
{
  hash_state hs;

  // 2: Perform SHA-256 hashing on the public key
  sha256_init(&hs);
  sha256_process(&hs,pubkey,pubkey_len);
  uint8_t sha_result[32]={0};
  sha256_done(&hs,sha_result);

  // 3: Perform RIPEMD-160 hashing on the result of SHA-256
  rmd160_init(&hs);
  rmd160_process(&hs,sha_result,32);
  uint8_t rmd_result[21]={0};
  rmd160_done(&hs,rmd_result+1); // +1 because: see next step

  // 4: Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
  rmd_result[0]=0x00;

  // 5: Perform SHA-256 hash on the extended RIPEMD-160 result
  sha256_init(&hs);
  sha256_process(&hs,rmd_result,21);
  sha256_done(&hs,sha_result);

  // 6: Perform SHA-256 hash on the result of the previous SHA-256 hash
  sha256_init(&hs);
  sha256_process(&hs,sha_result,32);
  sha256_done(&hs,sha_result);

  // 7: Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
  // 8: Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
  unsigned char bin_addr[256]={0};
  memcpy(bin_addr,rmd_result,21);
  memcpy(bin_addr+21,sha_result,4);

  char *r=EncodeBase58(bin_addr,bin_addr+25);

  strcpy(address,r);
  free(r);

  return 1;
}



// addr 16wfKZ6GQGND4YdasuiotRL1vuEyE6FXkH
// priv L2Ao9tDSMsNw9tAw9C1DvXXH95gnCkycgYn3MTYhbXe2J1ySMw7g

/*
0 0 0 0 0 0 0 0 0 0
0 0 0 0 0 0 0 0 0 0
0 0 0 0 0 0 80 93 b0 10
21 30 8 fb e2 61 6e 38 a2 80
ef 12 3e c9 25 73 19 45 79 c6
1e ce 99 5a 47 f8 39 22 88 1
48 30 71 4b


addr 1PtvNXHTMuEo9458o19MxHSpgmFsdC78JJ
priv KzZEmeU3JnUxapsdRhvRG3wrfZoN3K9KWViLTuoZqzVok3vE2hwm
*/

static const my_ltc_ecc_set_type ltc_secp256k1 = {
  32,                                                                  // key size in bytes
  "secp256k1",                                                         // name, not important
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",  //[v]   P
  "0000000000000000000000000000000000000000000000000000000000000000",  //[v]   A
  "0000000000000000000000000000000000000000000000000000000000000007",  //[v]   B
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",  //[v]   N (order)
  "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",  //[v]   Gx
  "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",  //[v]   Gy
};

//
// Modification of ecc_make_key_ex
// instead of generating a private key, it takes key as 1st param
//
static int ecc_make_key_from_bin(void *privkey, int priv_len, my_ecc_key *key, const my_ltc_ecc_set_type *dp)
{
   int            err;
   ecc_point     *base;
   void          *prime, *order, *a;
   unsigned char *buf;
   int            keysize;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);
   LTC_ARGCHK(dp          != NULL);


   key->idx = -1;
   key->dp  = dp;
   keysize  = dp->size;

   /* allocate ram */
   base = NULL;
   buf  =(unsigned char*) XMALLOC(ECC_MAXSIZE);
   if (buf == NULL) {
      return CRYPT_MEM;
   }

   // HAX: not a random value but private key's binary representation
   memset(buf,0,ECC_MAXSIZE);
   memcpy(buf,privkey,priv_len);

   /* setup the key variables */
   if ((err = mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, &prime, &order, &a, NULL)) != CRYPT_OK) {
      goto ERR_BUF;
   }
   base = ltc_ecc_new_point();
   if (base == NULL) {
      err = CRYPT_MEM;
      goto errkey;
   }

   /* read in the specs for this key */
   if ((err = mp_read_radix(prime,   (char *)key->dp->prime, 16)) != CRYPT_OK)                  { goto errkey; }
   if ((err = mp_read_radix(order,   (char *)key->dp->order, 16)) != CRYPT_OK)                  { goto errkey; }
   if ((err = mp_read_radix(a,       (char *)key->dp->A, 16)) != CRYPT_OK)                      { goto errkey; }
   if ((err = mp_read_radix(base->x, (char *)key->dp->Gx, 16)) != CRYPT_OK)                     { goto errkey; }
   if ((err = mp_read_radix(base->y, (char *)key->dp->Gy, 16)) != CRYPT_OK)                     { goto errkey; }
   if ((err = mp_set(base->z, 1)) != CRYPT_OK)                                                  { goto errkey; }
   if ((err = mp_read_unsigned_bin(key->k, (unsigned char *)buf, keysize)) != CRYPT_OK)         { goto errkey; }

   /* the key should be smaller than the order of base point */
   if (mp_cmp(key->k, order) != LTC_MP_LT) {
       if((err = mp_mod(key->k, order, key->k)) != CRYPT_OK)                                    { goto errkey; }
   }
   /* make the public key */
   if ((err = my_ltc_ecc_mulmod(key->k, base, &key->pubkey, prime, a, 1)) != CRYPT_OK)           { goto errkey; }
   key->type = PK_PRIVATE;

   /* free up ram */
   err = CRYPT_OK;
   goto cleanup;
errkey:
   mp_clear_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
cleanup:
   ltc_ecc_del_point(base);
   mp_clear_multi(prime, order, a, NULL);
ERR_BUF:
#ifdef LTC_CLEAN_STACK
   zeromem(buf, ECC_MAXSIZE);
#endif
   XFREE(buf);
   return err;
}


//
// Convert base58 wif to private key
//  in:   str_wif    - base58 encoded wif string
// out:   out_priv   - private key as binary data
//  in:   out_len    - length of out_priv buffer
// returns length of private key in bytes
static int private_key_from_wif(const char *str_wif,unsigned char *out_priv,size_t out_len)
{
  unsigned char *vkey;
  size_t vkey_len;

  vkey=DecodeBase58(str_wif,&vkey_len);

  if(vkey==NULL)
    return 0;

  if(str_wif[0]=='K' || str_wif[0]=='L')
      vkey_len-=5;
  else
      vkey_len-=4;

  memcpy(out_priv,vkey+1,vkey_len-1);
  free(vkey);

  return vkey_len-1;
}





//
// Compress a public key
//
static int pubkey_compress(unsigned char* pubkey,int len)
{
    if(len!=65)
        return 0;

    if(pubkey[len-1]%2==0)
        pubkey[0]=0x02;
    else pubkey[0]=0x03;

    return len-32;
}


static void bin2hex(unsigned char *buff,size_t buff_len,char *str,size_t str_len)
{
  char *pstr=str;
  for(int i=0;i<buff_len;i++)
  {
    sprintf(pstr, "%02x", buff[i]);
    pstr[0]=toupper(pstr[0]);
    pstr[1]=toupper(pstr[1]);
    pstr+=2;
  }
  *pstr=0;
}


int conv_privkey(char *pubkey,char *btc_addr,const char *str_wif)
{
  unsigned char key_priv[256];
  int priv_len=private_key_from_wif(str_wif,key_priv,sizeof(key_priv));

  my_ecc_key key={0};
  int ret=ecc_make_key_from_bin(key_priv,priv_len,&key,&ltc_secp256k1);
  if(ret!=CRYPT_OK)
  {
      ecc_free((ecc_key*)&key);
      return 0;
  }

  reverse_array((uint8_t*)key.pubkey.x,32);
  reverse_array((uint8_t*)key.pubkey.y,32);

  unsigned char bin_pub[65]={0};
  bin_pub[0]=0x04;
  memcpy(bin_pub+1, key.pubkey.x,32);
  memcpy(bin_pub+33,key.pubkey.y,32);
  int pub_len=pubkey_compress(bin_pub,65);

  bin2hex(bin_pub,pub_len,pubkey, KEYCONV_BUFF_LEN);

  ecc_free((ecc_key*)&key);

  return pubkey_to_address(btc_addr,bin_pub,pub_len);
}

