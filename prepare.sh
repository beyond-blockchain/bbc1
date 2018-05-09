#!/bin/sh

git clone https://github.com/openssl/openssl.git third_party/openssl
cd third_party/openssl
./config && make

cd ../libbbcsig
make clean
make
