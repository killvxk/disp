CC	= cc
INCLUDE = -I. -I..
CFLAGS	= $(INCLUDE) 
CFLAGS_INJECT = -std=gnu99 -ggdb
LDFLAGS = -L./
UNAME_M := $(shell uname -m)

TARGET= inject libdisp.so crypto rsa aes 
#TARGET= inject libdisp.so crypto rsa aes  trace
all: $(TARGET)

inject: utils.c ptrace.c inject.c 
	$(CC) $(CFLAGS) $(CFLAGS_INJECT) -o inject $^ -ldl

libdisp.so: libdisp.c  plthook.c hook_func_arr.c  hook.s 
	$(CC) $(CFLAGS) -Wa,--noexecstack -shared -o libdisp.so -fPIC $^ -lpthread -ldl
	@cp libdisp.so samples/

crypto: demo/crypto.c
	$(CC) $(CFLAGS) $(LDFLAGS) -O2 -o crypto $^ -lcrypto

aes: demo/aes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -O2 -o aes $^ -lgcrypt -ldisp

rsa: demo/rsa.c
	$(CC) $(CFLAGS) $(LDFLAGS) -O2 -o rsa $^ -lcrypto -ldisp
	@#$(CC) $(CFLAGS) -L./ -O2 -o rsa $^ -lcrypto

ssltest: demo/ssltest.c
	$(CC) $(CFLAGS) $(LDFLAGS) -O2 -o ssltest $^ -lcrypto -ldisp

trace: demo/trace.c
	$(CC) $(CFLAGS) $(LDFLAGS) -O2 -o $^ trace.c

clean:
	rm -f *.o $(TARGET) samples/libdisp.so
