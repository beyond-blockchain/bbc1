#!/bin/sh

git submodule init
git submodule update
cd third_party/openssl
./config && make

cd ../libbbcsig
make clean
make
