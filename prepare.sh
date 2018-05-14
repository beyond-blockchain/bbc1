#!/bin/sh

git clone https://github.com/openssl/openssl.git third_party/openssl
pushd third_party/openssl
git checkout f70425d3ac5e4ef17cfa116d99f8f03bbac1c7f2
./config && make
popd

pushd bbc1/core/libbbcsig
make clean
make
popd
