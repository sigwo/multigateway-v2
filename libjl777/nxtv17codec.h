// created by chanc3r
// MIT License

#ifndef nxt17codec_h
#define nxt17codec_h


#ifndef V17VERBOSE
#define V17VERBOSE 0
#endif
#define ENC_JSON_NAME "A1"  // we will change this for different versions...

#define V17DO if(V17VERBOSE)

#include "cJSON.h"

//encode v17 msg into original json
cJSON* v17encode(cJSON*);

//decode jssn msg into shorter v17 msg format
cJSON* v17decode(cJSON*);

#endif //last line

