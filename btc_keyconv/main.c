#include "btc_keyconv.h"
#include <tomcrypt.h>


// test wif from http://directory.io/904625697166532776746648320380374280100293470930272690489102837043110636675
int main()
{
  ltc_mp = tfm_desc; // place this line in main()

  char str_wif[]={"5Km2kuu7vtFDPpxywn4u3NLpbr5jKpTB3jsuDU2KYEqemcGibFR"};


  char pubkey[ KEYCONV_BUFF_LEN],btc_addr[KEYCONV_BUFF_LEN];
  conv_privkey(pubkey,btc_addr,str_wif);

  printf("wif:           %s\n",str_wif);
  printf("public key:    %s\n",pubkey);
  printf("address:       %s\n",btc_addr);

  printf("Press enter to close\n");
  getchar();
}
