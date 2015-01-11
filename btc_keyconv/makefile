CC=gcc
CFLAGS=-std=c99 -I./include -L./ -ltomcrypt -ltfm -DLTC_SOURCE -DTFM_DESC -DUSE_TFM



OBJ=base58.o tomcrypt_branch.o btc_keyconv.o main.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)


btc_keyconv: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)