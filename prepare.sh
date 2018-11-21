#!/bin/bash

rm -rf libs
mkdir -p libs
git clone -b master https://github.com/beyond-blockchain/libbbcsig.git libs
cd libs
bash prepare.sh

cd lib
if [ -f libbbcsig.dylib ]; then
  cp libbbcsig.dylib ../../bbc1/core/libs/
elif [ -f libbbcsig.so ]; then
  cp libbbcsig.so ../../bbc1/core/libs/
fi
