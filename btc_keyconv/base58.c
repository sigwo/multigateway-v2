#include "base58.h"
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#include <stdlib.h>

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


unsigned char *DecodeBase58(const char *psz, size_t *vch_len) {
    *vch_len=0;
    uint8_t *vch;

    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    unsigned b256_size=strlen(psz) * 733 / 1000 + 1;
    uint8_t *b256=(uint8_t*)malloc(b256_size); // log(58) / log(256), rounded up.
    memset(b256,0,b256_size);

    // Process the characters.
    while (*psz && !isspace(*psz)) {
        // Decode base58 character
        const char *ch = strchr(pszBase58, *psz);
        if (ch == NULL)
        {
            free(b256);
            return false;
        }

        // Apply "b256 = b256 * 58 + ch".
        int carry = ch - pszBase58;
        for (int i=b256_size-1; i>=0; i--) {
            carry += 58 * (unsigned)(b256[i]);
            b256[i] = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0)
    {
        free(b256);
        return false;
    }

    // Skip leading zeroes in b256.
    int i=0;
    while ( i!= b256_size && b256[i] == 0)
        i++;

    // Copy result into output vector.

    *vch_len=zeroes+(b256_size-i);

    vch=(uint8_t*)malloc(*vch_len);
    memset(vch,0,zeroes);
    int j=0;
    while (i != b256_size-1)
    {
        vch[j]=b256[i];
        i++;
        j++;
    }
    free(b256);
    return vch;
}

char *EncodeBase58(const unsigned char* pbegin, const unsigned char* pend) {
    // Skip & count leading zeroes.
    int zeroes = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.

    unsigned b58_size=(pend - pbegin) * 138 / 100 + 1;
    uint8_t *b58=(uint8_t*)malloc(b58_size); // log(256) / log(58), rounded up.
    memset(b58,0,b58_size);
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        // Apply "b58 = b58 * 256 + ch".
        for (int i=b58_size-1; i>=0; i--) {
            carry += 256 * (b58[i]);
            b58[i] = carry % 58;
            carry /= 58;
        }
        assert(carry == 0);
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    int i=0;
    while (i<b58_size && b58[i] == 0)
        i++;
    i--;
    // Translate the result into a string.
    char *str=(char*)malloc(zeroes + (b58_size - i));
    memset(str,'1',zeroes);

    int j=0;
    while (i < b58_size)
    {
        str[j] = pszBase58[b58[i]];
        j++;
        i++;
    }
    str[j]='\0';

    return str;
}

