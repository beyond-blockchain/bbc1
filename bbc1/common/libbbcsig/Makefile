CC = gcc
OPENSSL_DIR=../../../third_party/openssl
INCS = -I$(OPENSSL_DIR)/include -I$(OPENSSL_DIR)
LIBS = $(OPENSSL_DIR)/libssl.a $(OPENSSL_DIR)/libcrypto.a

.c.o:
	$(CC) $(INCS) -c $<

all:
	make libbbcsig.so

libbbcsig.so:	libbbcsig.o
	gcc -shared -o $@ $(LIBS) $<
	install -m 0644 $@ ../

openssl:
	cd $(OPENSSL_DIR) && ./config && make

clean:
	rm -f libbbcsig.so libbbcsig.o

