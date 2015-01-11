#ifndef BASE58_H
#define BASE58_H

#include <stdint.h>

// functions allocate memory themselves (return values)

//  in: psz       - string to decode
// out: vch_len   - length of returned buffer
unsigned char *DecodeBase58(const char *psz,size_t *vch_len);

char *EncodeBase58(const unsigned char* pbegin, const unsigned char* pend);




#endif // BASE58_H

