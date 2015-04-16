#include <stdio.h>
main()
{
int i; for (i=0; i<10; i++) printf("count.%d\n",i), fflush(stdout), sleep(1);
}
