CC	= cc
INCLUDE = -I. -I.. -I./Mastik/src
CFLAGS_MASTIK = -DNDEBUG
CFLAGS_INJECT = -ggdb
CFLAGS	= $(INCLUDE) -g -O2 -std=gnu99  $(CLFAGS_MASTIK)
ASFLAGS = -Wa,--noexecstack
LDFLAGS = -L./ -L./Mastik/src
UNAME_M := $(shell uname -m)
VPATH = ./:./Mastik/src

TARGET= inject libdisp.so crypto rsa aes wolf-aes rsa_gcrypt
#TARGET= inject libdisp.so crypto rsa aes  trace
all: $(TARGET)

inject: utils.c ptrace.c inject.c 
	$(CC) $(CFLAGS) $(CFLAGS_INJECT) -o inject $^ -ldl

libdisp.so: libdisp.c library_hook.c plthook.c hook_func_arr.c  hook.s fr.c vlist.c timestats.c
	$(CC) $(LDFLAGS) $(CFLAGS) $(ASFLAGS) -shared -o libdisp.so -fPIC $^ -lpthread -ldl
	@cp libdisp.so samples/

crypto: demo/crypto.c
	$(CC) $(CFLAGS) $(LDFLAGS) -O2 -o crypto $^ -lcrypto -ldisp

aes: demo/aes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o aes $^ -lgcrypt -ldisp

rsa: demo/rsa.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o rsa $^ -lcrypto -ldisp
	@#$(CC) $(CFLAGS) -L./ -o rsa $^ -lcrypto

rsa_gcrypt: demo/rsa_gcrypt.c demo/gcry.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o rsa_gcrypt $^ -lgcrypt -ldisp

ssltest: demo/ssltest.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o ssltest $^ -lcrypto -ldisp

trace: demo/trace.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $^ trace.c

wolf-aes: demo/wolf-aes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o wolf-aes $^ -lwolfssl

clean:
	rm -f *.o $(TARGET) samples/libdisp.so
