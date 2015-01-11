
* required #defines (place in files or as compiler flags) : 
TFM_DESC
USE_TFM
LTC_SOURCE

* libs:
tomcrypt
tfm (tom's fast math)

* possible linking porblems:
if linker complains that there are some undefined functions from tomsfastmath, you might need to recompile libtomcrypt.
you will need to modify libtomcrypt makefile and add the following line
CFLAGS += -DTFM_DESC -I../path_to_tomsfastmath-0.12/src/headers -L../path_to_tomsfastmath-0.12  -ltfm

Example: see main.c