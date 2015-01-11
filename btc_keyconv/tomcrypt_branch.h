#ifndef TOMCRYPT_BRANCH_H
#define TOMCRYPT_BRANCH_H

#include "tomcrypt.h"

/** Structure defines a NIST GF(p) curve */
typedef struct {
   /** The size of the curve in octets */
   int size;

   /** name of curve */
   char *name;

   /** The prime that defines the field the curve is in (encoded in hex) */
   char *prime;

	 /** The fields A param (hex) */
	 char *A;

   /** The fields B param (hex) */
   char *B;

   /** The order of the curve (hex) */
   char *order;

   /** The x co-ordinate of the base point on the curve (hex) */
   char *Gx;

   /** The y co-ordinate of the base point on the curve (hex) */
   char *Gy;
} my_ltc_ecc_set_type;


typedef struct {
    /** Type of key, PK_PRIVATE or PK_PUBLIC */
    int type;

    /** Index into the ltc_ecc_sets[] for the parameters of this curve; if -1, then this key is using user supplied curve in dp */
    int idx;

	/** pointer to domain parameters; either points to NIST curves (identified by idx >= 0) or user supplied curve */
	const my_ltc_ecc_set_type *dp;

    /** The public key */
    ecc_point pubkey;

    /** The private key */
    void *k;
} my_ecc_key;


/* R = kG */
int my_ltc_ecc_mulmod(void *k, ecc_point *G, ecc_point *R, void *modulus, void *a, int map);

#endif // TOMCRYPT_BRANCH_H
