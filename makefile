CC?=gcc

ifneq ("", "$(MSS_HEIGHT)")
    MSS_PARAMS:= -DMSS_HEIGHT=$(MSS_HEIGHT)
else	
    MSS_PARAMS:= -DMSS_HEIGHT=10
endif
ifneq ("","$(MSS_K)")
    MSS_PARAMS+= -DMSS_K=$(MSS_K)
else
    MSS_PARAMS+= -DMSS_K=2
endif
ifneq ("","$(WINTERNITZ_W)")
    MSS_PARAMS+=-DWINTERNITZ_W=$(WINTERNITZ_W)
else 
    MSS_PARAMS+=-DWINTERNITZ_W=2
endif

CFLAGS=-std=c99 -g -Wall -pedantic -I include $(MSS_PARAMS)
MSS_OBJS=bin/winternitz.o bin/util.o bin/hash.o bin/sha2.o bin/aes.o bin/ti_aes.o


all:	execs winternitz mss libs

ti_aes:	src/ti_aes.c
		mkdir -p bin
		$(CC) src/ti_aes.c -c -o bin/ti_aes.o $(CFLAGS)
		
aes:	src/aes_128.c
		make ti_aes
		$(CC) src/aes_128.c -c -o bin/aes.o $(CFLAGS)

sha2:   src/sha2.c		
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

hash:   src/hash.c
		make aes
		make sha2
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

util:	src/util.c
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

winternitz:	src/winternitz.c
		make hash		
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

mss:	src/mss.c
		make winternitz
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

execs:	src/winternitz.c src/util.c src/test.c
		make winternitz
		make util
		$(CC) src/bench.c src/mss.c -o bin/mss-bench $(MSS_OBJS) $(CFLAGS)
		$(CC) src/test.c src/mss.c -o bin/mss-test -DVERBOSE -DSERIALIZATION -DSELF_TEST $(MSS_OBJS) $(CFLAGS)

libs:
		gcc -c -fPIC -o bin/dyn_ti_aes.o src/ti_aes.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_sha2.o src/sha2.c $(CFLAGS)	
		gcc -c -fPIC -o bin/dyn_aes.o src/aes_128.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_hash.o src/hash.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_util.o src/util.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_test.o src/test.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_winternitz.o src/winternitz.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_mss.o src/mss.c $(CFLAGS)
		gcc -shared -Wl,-install_name,libcrypto.so -o bin/libcrypto.so bin/dyn_*.o -lc
		ar rcs bin/libcrypto.a bin/aes.o bin/sha2.o bin/hash.o bin/winternitz.o bin/util.o bin/mss.o
clean:		
		rm -rf *.o bin/* lib/*
