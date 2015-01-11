

#include "tomcrypt_branch.h"
#include "tomcrypt.h"


/*
  @file ltc_ecc_projective_dbl_point.c
  ECC Crypto, Tom St Denis
*/

#if defined(LTC_MECC) && (!defined(LTC_MECC_ACCEL) || defined(LTM_LTC_DESC))

/**
   Double an ECC point
   @param P   The point to double
   @param R   [out] The destination of the double
   @param modulus  The modulus of the field the ECC curve is in
   @param          The a parameter of the ECC curve
   @param mp       The "b" value from montgomery_setup()
   @return CRYPT_OK on success
*/
static int my_ltc_ecc_projective_dbl_point(ecc_point *P, ecc_point *R, void *modulus, void *a, void *mp)
{
   void *t1, *t2;
   int   err;

   LTC_ARGCHK(P       != NULL);
   LTC_ARGCHK(R       != NULL);
   LTC_ARGCHK(modulus != NULL);
   LTC_ARGCHK(a       != NULL);
   LTC_ARGCHK(mp      != NULL);

   if ((err = mp_init_multi(&t1, &t2, NULL)) != CRYPT_OK) {
      return err;
   }

   if (P != R) {
      if ((err = mp_copy(P->x, R->x)) != CRYPT_OK)                                { goto done; }
      if ((err = mp_copy(P->y, R->y)) != CRYPT_OK)                                { goto done; }
      if ((err = mp_copy(P->z, R->z)) != CRYPT_OK)                                { goto done; }
   }

   /* T1 = X * X */
   if ((err = mp_sqr(R->x, t1)) != CRYPT_OK)                                      { goto done; }
   if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)                 { goto done; }

   /* T2 = 2T1 */
   if ((err = mp_add(t1, t1, t2)) != CRYPT_OK)                                    { goto done; }
   if (mp_cmp(t2, modulus) != LTC_MP_LT) {
     if ((err = mp_sub(t2, modulus, t2)) != CRYPT_OK)                             { goto done; }
   }
   /* T2 = T2 + T1 */
   if ((err = mp_add(t1, t2, t2)) != CRYPT_OK)                                    { goto done; }
   if (mp_cmp(t2, modulus) != LTC_MP_LT) {
     if ((err = mp_sub(t2, modulus, t2)) != CRYPT_OK)                             { goto done; }
   }
   if (mp_iszero(a)) {
      /* T1 = T2 */
      mp_copy(t2, t1);
   } else {
      /* T1 = Z ^ 4 */
      if ((err = mp_sqr(R->z, t1)) != CRYPT_OK)                                      { goto done; }
      if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)                 { goto done; }
      if ((err = mp_sqr(t1, t1)) != CRYPT_OK)                                        { goto done; }
      if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)                 { goto done; }
      /* T1 = T1 * A */
      if ((err = mp_mul(t1, a, t1)) != CRYPT_OK)                                     { goto done; }
      if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)                 { goto done; }
      /* T1 = T1 + T2 */
      if ((err = mp_add(t1, t2, t1)) != CRYPT_OK)                                    { goto done; }
      if (mp_cmp(t1, modulus) != LTC_MP_LT) {
         if ((err = mp_sub(t1, modulus, t1)) != CRYPT_OK)                            { goto done; }
      }
   }

   /* Z = Y * Z */
   if ((err = mp_mul(R->z, R->y, R->z)) != CRYPT_OK)                              { goto done; }
   if ((err = mp_montgomery_reduce(R->z, modulus, mp)) != CRYPT_OK)               { goto done; }
   /* Z = 2Z */
   if ((err = mp_add(R->z, R->z, R->z)) != CRYPT_OK)                              { goto done; }
   if (mp_cmp(R->z, modulus) != LTC_MP_LT) {
      if ((err = mp_sub(R->z, modulus, R->z)) != CRYPT_OK)                        { goto done; }
   }

   /* Y = 2Y */
   if ((err = mp_add(R->y, R->y, R->y)) != CRYPT_OK)                              { goto done; }
   if (mp_cmp(R->y, modulus) != LTC_MP_LT) {
      if ((err = mp_sub(R->y, modulus, R->y)) != CRYPT_OK)                        { goto done; }
   }
   /* Y = Y * Y */
   if ((err = mp_sqr(R->y, R->y)) != CRYPT_OK)                                    { goto done; }
   if ((err = mp_montgomery_reduce(R->y, modulus, mp)) != CRYPT_OK)               { goto done; }
   /* T2 = Y * Y */
   if ((err = mp_sqr(R->y, t2)) != CRYPT_OK)                                      { goto done; }
   if ((err = mp_montgomery_reduce(t2, modulus, mp)) != CRYPT_OK)                 { goto done; }
   /* T2 = T2/2 */
   if (mp_isodd(t2)) {
      if ((err = mp_add(t2, modulus, t2)) != CRYPT_OK)                            { goto done; }
   }
   if ((err = mp_div_2(t2, t2)) != CRYPT_OK)                                      { goto done; }
   /* Y = Y * X */
   if ((err = mp_mul(R->y, R->x, R->y)) != CRYPT_OK)                              { goto done; }
   if ((err = mp_montgomery_reduce(R->y, modulus, mp)) != CRYPT_OK)               { goto done; }

   /* X  = T1 * T1 */
   if ((err = mp_sqr(t1, R->x)) != CRYPT_OK)                                      { goto done; }
   if ((err = mp_montgomery_reduce(R->x, modulus, mp)) != CRYPT_OK)               { goto done; }
   /* X = X - Y */
   if ((err = mp_sub(R->x, R->y, R->x)) != CRYPT_OK)                              { goto done; }
   if (mp_cmp_d(R->x, 0) == LTC_MP_LT) {
      if ((err = mp_add(R->x, modulus, R->x)) != CRYPT_OK)                        { goto done; }
   }
   /* X = X - Y */
   if ((err = mp_sub(R->x, R->y, R->x)) != CRYPT_OK)                              { goto done; }
   if (mp_cmp_d(R->x, 0) == LTC_MP_LT) {
      if ((err = mp_add(R->x, modulus, R->x)) != CRYPT_OK)                        { goto done; }
   }

   /* Y = Y - X */
   if ((err = mp_sub(R->y, R->x, R->y)) != CRYPT_OK)                              { goto done; }
   if (mp_cmp_d(R->y, 0) == LTC_MP_LT) {
      if ((err = mp_add(R->y, modulus, R->y)) != CRYPT_OK)                        { goto done; }
   }
   /* Y = Y * T1 */
   if ((err = mp_mul(R->y, t1, R->y)) != CRYPT_OK)                                { goto done; }
   if ((err = mp_montgomery_reduce(R->y, modulus, mp)) != CRYPT_OK)               { goto done; }
   /* Y = Y - T2 */
   if ((err = mp_sub(R->y, t2, R->y)) != CRYPT_OK)                                { goto done; }
   if (mp_cmp_d(R->y, 0) == LTC_MP_LT) {
      if ((err = mp_add(R->y, modulus, R->y)) != CRYPT_OK)                        { goto done; }
   }

   err = CRYPT_OK;
done:
   mp_clear_multi(t1, t2, NULL);
   return err;
}
#endif


/**
  @file ltc_ecc_projective_add_point.c
  ECC Crypto, Tom St Denis
*/

#if defined(LTC_MECC) && (!defined(LTC_MECC_ACCEL) || defined(LTM_LTC_DESC))

/**
   Add two ECC points
   @param P        The point to add
   @param Q        The point to add
   @param R        [out] The destination of the double
   @param modulus  The modulus of the field the ECC curve is in
   @param a        The A parameter of the ECC curve
   @param mp       The "b" value from montgomery_setup()
   @return CRYPT_OK on success
*/
static int my_ltc_ecc_projective_add_point(ecc_point *P, ecc_point *Q, ecc_point *R, void *modulus, void *a, void *mp)
{
   void  *t1, *t2, *x, *y, *z;
   int    err;

   LTC_ARGCHK(P       != NULL);
   LTC_ARGCHK(Q       != NULL);
   LTC_ARGCHK(R       != NULL);
   LTC_ARGCHK(modulus != NULL);
   LTC_ARGCHK(mp      != NULL);

   if ((err = mp_init_multi(&t1, &t2, &x, &y, &z, NULL)) != CRYPT_OK) {
      return err;
   }

   /* should we dbl instead? */
   if ((err = mp_sub(modulus, Q->y, t1)) != CRYPT_OK)                          { goto done; }

   if ( (mp_cmp(P->x, Q->x) == LTC_MP_EQ) &&
        (Q->z != NULL && mp_cmp(P->z, Q->z) == LTC_MP_EQ) &&
        (mp_cmp(P->y, Q->y) == LTC_MP_EQ || mp_cmp(P->y, t1) == LTC_MP_EQ)) {
        mp_clear_multi(t1, t2, x, y, z, NULL);
        return my_ltc_ecc_projective_dbl_point(P, R, modulus, a, mp);
   }

   if ((err = mp_copy(P->x, x)) != CRYPT_OK)                                   { goto done; }
   if ((err = mp_copy(P->y, y)) != CRYPT_OK)                                   { goto done; }
   if ((err = mp_copy(P->z, z)) != CRYPT_OK)                                   { goto done; }

   /* if Z is one then these are no-operations */
   if (Q->z != NULL) {
      /* T1 = Z' * Z' */
      if ((err = mp_sqr(Q->z, t1)) != CRYPT_OK)                                { goto done; }
      if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)           { goto done; }
      /* X = X * T1 */
      if ((err = mp_mul(t1, x, x)) != CRYPT_OK)                                { goto done; }
      if ((err = mp_montgomery_reduce(x, modulus, mp)) != CRYPT_OK)            { goto done; }
      /* T1 = Z' * T1 */
      if ((err = mp_mul(Q->z, t1, t1)) != CRYPT_OK)                            { goto done; }
      if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)           { goto done; }
      /* Y = Y * T1 */
      if ((err = mp_mul(t1, y, y)) != CRYPT_OK)                                { goto done; }
      if ((err = mp_montgomery_reduce(y, modulus, mp)) != CRYPT_OK)            { goto done; }
   }

   /* T1 = Z*Z */
   if ((err = mp_sqr(z, t1)) != CRYPT_OK)                                      { goto done; }
   if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)              { goto done; }
   /* T2 = X' * T1 */
   if ((err = mp_mul(Q->x, t1, t2)) != CRYPT_OK)                               { goto done; }
   if ((err = mp_montgomery_reduce(t2, modulus, mp)) != CRYPT_OK)              { goto done; }
   /* T1 = Z * T1 */
   if ((err = mp_mul(z, t1, t1)) != CRYPT_OK)                                  { goto done; }
   if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)              { goto done; }
   /* T1 = Y' * T1 */
   if ((err = mp_mul(Q->y, t1, t1)) != CRYPT_OK)                               { goto done; }
   if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)              { goto done; }

   /* Y = Y - T1 */
   if ((err = mp_sub(y, t1, y)) != CRYPT_OK)                                   { goto done; }
   if (mp_cmp_d(y, 0) == LTC_MP_LT) {
      if ((err = mp_add(y, modulus, y)) != CRYPT_OK)                           { goto done; }
   }
   /* T1 = 2T1 */
   if ((err = mp_add(t1, t1, t1)) != CRYPT_OK)                                 { goto done; }
   if (mp_cmp(t1, modulus) != LTC_MP_LT) {
      if ((err = mp_sub(t1, modulus, t1)) != CRYPT_OK)                         { goto done; }
   }
   /* T1 = Y + T1 */
   if ((err = mp_add(t1, y, t1)) != CRYPT_OK)                                  { goto done; }
   if (mp_cmp(t1, modulus) != LTC_MP_LT) {
      if ((err = mp_sub(t1, modulus, t1)) != CRYPT_OK)                         { goto done; }
   }
   /* X = X - T2 */
   if ((err = mp_sub(x, t2, x)) != CRYPT_OK)                                   { goto done; }
   if (mp_cmp_d(x, 0) == LTC_MP_LT) {
      if ((err = mp_add(x, modulus, x)) != CRYPT_OK)                           { goto done; }
   }
   /* T2 = 2T2 */
   if ((err = mp_add(t2, t2, t2)) != CRYPT_OK)                                 { goto done; }
   if (mp_cmp(t2, modulus) != LTC_MP_LT) {
      if ((err = mp_sub(t2, modulus, t2)) != CRYPT_OK)                         { goto done; }
   }
   /* T2 = X + T2 */
   if ((err = mp_add(t2, x, t2)) != CRYPT_OK)                                  { goto done; }
   if (mp_cmp(t2, modulus) != LTC_MP_LT) {
      if ((err = mp_sub(t2, modulus, t2)) != CRYPT_OK)                         { goto done; }
   }

   /* if Z' != 1 */
   if (Q->z != NULL) {
      /* Z = Z * Z' */
      if ((err = mp_mul(z, Q->z, z)) != CRYPT_OK)                              { goto done; }
      if ((err = mp_montgomery_reduce(z, modulus, mp)) != CRYPT_OK)            { goto done; }
   }

   /* Z = Z * X */
   if ((err = mp_mul(z, x, z)) != CRYPT_OK)                                    { goto done; }
   if ((err = mp_montgomery_reduce(z, modulus, mp)) != CRYPT_OK)               { goto done; }

   /* T1 = T1 * X  */
   if ((err = mp_mul(t1, x, t1)) != CRYPT_OK)                                  { goto done; }
   if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)              { goto done; }
   /* X = X * X */
   if ((err = mp_sqr(x, x)) != CRYPT_OK)                                       { goto done; }
   if ((err = mp_montgomery_reduce(x, modulus, mp)) != CRYPT_OK)               { goto done; }
   /* T2 = T2 * x */
   if ((err = mp_mul(t2, x, t2)) != CRYPT_OK)                                  { goto done; }
   if ((err = mp_montgomery_reduce(t2, modulus, mp)) != CRYPT_OK)              { goto done; }
   /* T1 = T1 * X  */
   if ((err = mp_mul(t1, x, t1)) != CRYPT_OK)                                  { goto done; }
   if ((err = mp_montgomery_reduce(t1, modulus, mp)) != CRYPT_OK)              { goto done; }

   /* X = Y*Y */
   if ((err = mp_sqr(y, x)) != CRYPT_OK)                                       { goto done; }
   if ((err = mp_montgomery_reduce(x, modulus, mp)) != CRYPT_OK)               { goto done; }
   /* X = X - T2 */
   if ((err = mp_sub(x, t2, x)) != CRYPT_OK)                                   { goto done; }
   if (mp_cmp_d(x, 0) == LTC_MP_LT) {
      if ((err = mp_add(x, modulus, x)) != CRYPT_OK)                           { goto done; }
   }

   /* T2 = T2 - X */
   if ((err = mp_sub(t2, x, t2)) != CRYPT_OK)                                  { goto done; }
   if (mp_cmp_d(t2, 0) == LTC_MP_LT) {
      if ((err = mp_add(t2, modulus, t2)) != CRYPT_OK)                         { goto done; }
   }
   /* T2 = T2 - X */
   if ((err = mp_sub(t2, x, t2)) != CRYPT_OK)                                  { goto done; }
   if (mp_cmp_d(t2, 0) == LTC_MP_LT) {
      if ((err = mp_add(t2, modulus, t2)) != CRYPT_OK)                         { goto done; }
   }
   /* T2 = T2 * Y */
   if ((err = mp_mul(t2, y, t2)) != CRYPT_OK)                                  { goto done; }
   if ((err = mp_montgomery_reduce(t2, modulus, mp)) != CRYPT_OK)              { goto done; }
   /* Y = T2 - T1 */
   if ((err = mp_sub(t2, t1, y)) != CRYPT_OK)                                  { goto done; }
   if (mp_cmp_d(y, 0) == LTC_MP_LT) {
      if ((err = mp_add(y, modulus, y)) != CRYPT_OK)                           { goto done; }
   }
   /* Y = Y/2 */
   if (mp_isodd(y)) {
      if ((err = mp_add(y, modulus, y)) != CRYPT_OK)                           { goto done; }
   }
   if ((err = mp_div_2(y, y)) != CRYPT_OK)                                     { goto done; }

   if ((err = mp_copy(x, R->x)) != CRYPT_OK)                                   { goto done; }
   if ((err = mp_copy(y, R->y)) != CRYPT_OK)                                   { goto done; }
   if ((err = mp_copy(z, R->z)) != CRYPT_OK)                                   { goto done; }

   err = CRYPT_OK;
done:
   mp_clear_multi(t1, t2, x, y, z, NULL);
   return err;
}

#endif





#ifdef LTC_MECC
#ifndef LTC_ECC_TIMING_RESISTANT

/* size of sliding window, don't change this! */
#define WINSIZE 4

/**
   Perform a point multiplication
   @param k    The scalar to multiply by
   @param G    The base point
   @param R    [out] Destination for kG
   @param modulus  The modulus of the field the ECC curve is in
   @param a    The A parameter of the ECC curve
   @param map      Boolean whether to map back to affine or not (1==map, 0 == leave in projective)
   @return CRYPT_OK on success
*/
int my_ltc_ecc_mulmod(void *k, ecc_point *G, ecc_point *R, void *modulus, void *a, int map)
{
   ecc_point *tG, *M[8];
   int        i, j, err;
   void       *mu, *mp;
   unsigned long buf;
   int        first, bitbuf, bitcpy, bitcnt, mode, digidx;

   LTC_ARGCHK(k       != NULL);
   LTC_ARGCHK(G       != NULL);
   LTC_ARGCHK(R       != NULL);
   LTC_ARGCHK(modulus != NULL);
   LTC_ARGCHK(a       != NULL);

   /* init montgomery reduction */
   if ((err = mp_montgomery_setup(modulus, &mp)) != CRYPT_OK) {
      return err;
   }
   if ((err = mp_init(&mu)) != CRYPT_OK) {
      mp_montgomery_free(mp);
      return err;
   }
   if ((err = mp_montgomery_normalization(mu, modulus)) != CRYPT_OK) {
      mp_montgomery_free(mp);
      mp_clear(mu);
      return err;
   }

  /* alloc ram for window temps */
  for (i = 0; i < 8; i++) {
      M[i] = ltc_ecc_new_point();
      if (M[i] == NULL) {
         for (j = 0; j < i; j++) {
             ltc_ecc_del_point(M[j]);
         }
         mp_montgomery_free(mp);
         mp_clear(mu);
         return CRYPT_MEM;
      }
  }

   /* make a copy of G incase R==G */
   tG = ltc_ecc_new_point();
   if (tG == NULL)                                                                   { err = CRYPT_MEM; goto done; }

   /* tG = G  and convert to montgomery */
   if (mp_cmp_d(mu, 1) == LTC_MP_EQ) {
      if ((err = mp_copy(G->x, tG->x)) != CRYPT_OK)                                  { goto done; }
      if ((err = mp_copy(G->y, tG->y)) != CRYPT_OK)                                  { goto done; }
      if ((err = mp_copy(G->z, tG->z)) != CRYPT_OK)                                  { goto done; }
   } else {
      if ((err = mp_mulmod(G->x, mu, modulus, tG->x)) != CRYPT_OK)                   { goto done; }
      if ((err = mp_mulmod(G->y, mu, modulus, tG->y)) != CRYPT_OK)                   { goto done; }
      if ((err = mp_mulmod(G->z, mu, modulus, tG->z)) != CRYPT_OK)                   { goto done; }
   }
   mp_clear(mu);
   mu = NULL;

   /* calc the M tab, which holds kG for k==8..15 */
   /* M[0] == 8G */
   if ((err = my_ltc_ecc_projective_dbl_point(tG, M[0], modulus, a, mp)) != CRYPT_OK)              { goto done; }
   if ((err = my_ltc_ecc_projective_dbl_point(M[0], M[0], modulus, a, mp)) != CRYPT_OK)            { goto done; }
   if ((err = my_ltc_ecc_projective_dbl_point(M[0], M[0], modulus, a, mp)) != CRYPT_OK)            { goto done; }

   /* now find (8+k)G for k=1..7 */
   for (j = 9; j < 16; j++) {
       if ((err = my_ltc_ecc_projective_add_point(M[j-9], tG, M[j-8], modulus, a, mp)) != CRYPT_OK) { goto done; }
   }

   /* setup sliding window */
   mode   = 0;
   bitcnt = 1;
   buf    = 0;
   digidx = mp_get_digit_count(k) - 1;
   bitcpy = bitbuf = 0;
   first  = 1;

   /* perform ops */
   for (;;) {
     /* grab next digit as required */
     if (--bitcnt == 0) {
       if (digidx == -1) {
          break;
       }
       buf    = mp_get_digit(k, digidx);
       bitcnt = (int) ltc_mp.bits_per_digit;
       --digidx;
     }

     /* grab the next msb from the ltiplicand */
     i = (buf >> (ltc_mp.bits_per_digit - 1)) & 1;
     buf <<= 1;

     /* skip leading zero bits */
     if (mode == 0 && i == 0) {
        continue;
     }

     /* if the bit is zero and mode == 1 then we double */
     if (mode == 1 && i == 0) {
        if ((err = my_ltc_ecc_projective_dbl_point(R, R, modulus, a, mp)) != CRYPT_OK)              { goto done; }
        continue;
     }

     /* else we add it to the window */
     bitbuf |= (i << (WINSIZE - ++bitcpy));
     mode = 2;

     if (bitcpy == WINSIZE) {
       /* if this is the first window we do a simple copy */
       if (first == 1) {
          /* R = kG [k = first window] */
          if ((err = mp_copy(M[bitbuf-8]->x, R->x)) != CRYPT_OK)                     { goto done; }
          if ((err = mp_copy(M[bitbuf-8]->y, R->y)) != CRYPT_OK)                     { goto done; }
          if ((err = mp_copy(M[bitbuf-8]->z, R->z)) != CRYPT_OK)                     { goto done; }
          first = 0;
       } else {
         /* normal window */
         /* ok window is filled so double as required and add  */
         /* double first */
         for (j = 0; j < WINSIZE; j++) {
           if ((err =my_ltc_ecc_projective_dbl_point(R, R, modulus, a, mp)) != CRYPT_OK)           { goto done; }
         }

         /* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranteed */
         if ((err = my_ltc_ecc_projective_add_point(R, M[bitbuf-8], R, modulus, a, mp)) != CRYPT_OK) { goto done; }
       }
       /* empty window and reset */
       bitcpy = bitbuf = 0;
       mode = 1;
    }
  }

   /* if bits remain then double/add */
   if (mode == 2 && bitcpy > 0) {
     /* double then add */
     for (j = 0; j < bitcpy; j++) {
       /* only double if we have had at least one add first */
       if (first == 0) {
          if ((err = my_ltc_ecc_projective_dbl_point(R, R, modulus, a, mp)) != CRYPT_OK)           { goto done; }
       }

       bitbuf <<= 1;
       if ((bitbuf & (1 << WINSIZE)) != 0) {
         if (first == 1){
            /* first add, so copy */
            if ((err = mp_copy(tG->x, R->x)) != CRYPT_OK)                           { goto done; }
            if ((err = mp_copy(tG->y, R->y)) != CRYPT_OK)                           { goto done; }
            if ((err = mp_copy(tG->z, R->z)) != CRYPT_OK)                           { goto done; }
            first = 0;
         } else {
            /* then add */
            if ((err = my_ltc_ecc_projective_add_point(R, tG, R, modulus, a, mp)) != CRYPT_OK)     { goto done; }
         }
       }
     }
   }

   /* map R back from projective space */
   if (map) {
      err = ltc_ecc_map(R, modulus, mp);
   } else {
      err = CRYPT_OK;
   }
done:
   if (mu != NULL) {
      mp_clear(mu);
   }
   mp_montgomery_free(mp);
   ltc_ecc_del_point(tG);
   for (i = 0; i < 8; i++) {
       ltc_ecc_del_point(M[i]);
   }
   return err;
}

#endif

#undef WINSIZE

#endif
