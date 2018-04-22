#!/bin/sh

git submodule init
git submodule update
cd third_party/openssl
./config && make

cd ../../bbc1/core/libbbcsig/
make
