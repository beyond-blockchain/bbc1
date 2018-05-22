#!/bin/sh

git clone https://github.com/openssl/openssl.git libs/openssl
cd libs/openssl
git checkout f70425d3ac5e4ef17cfa116d99f8f03bbac1c7f2
./config && make

cd ../libbbcsig
make clean
make
