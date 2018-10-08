CC = gcc
OPENSSL_DIR=../openssl
INCS = -I$(OPENSSL_DIR)/include -I$(OPENSSL_DIR)
LIBS = $(OPENSSL_DIR)/libssl.a $(OPENSSL_DIR)/libcrypto.a

UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
LFLAGS0 = 
LFLAGS1 = 
LFLAGS2 =
TARGET = libbbcsig.dylib
else
LFLAGS0 = -fPIC
LFLAGS1 = -Wl,--whole-archive
LFLAGS2 = -Wl,--no-whole-archive
TARGET = libbbcsig.so
endif

.c.o:
	$(CC) $(INCS) $(LFLAGS0) -c $<

all:
	make $(TARGET)

libbbcsig.so:	libbbcsig.o
	gcc -shared -o $@ $(LFLAGS1) $(LIBS) $(LFLAGS2) $<
	install -m 0644 $@ ../../bbc1/core/

libbbcsig.dylib:	libbbcsig.o
	gcc -shared -o $@ $(LFLAGS1) $(LIBS) $(LFLAGS2) $<
	install -m 0644 $@ ../../bbc1/core/

openssl:
	cd $(OPENSSL_DIR) && ./config && make

clean:
	rm -f libbbcsig.so libbbcsig.dylib libbbcsig.o

