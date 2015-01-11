#ifndef BTC_KEYCONV_H
#define BTC_KEYCONV_H

#define KEYCONV_BUFF_LEN 256


int conv_privkey(char *pubkey,char *btc_addr,const char *str_wif);


#endif // BTC_KEYCONV_H
