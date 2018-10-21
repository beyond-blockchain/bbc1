#!/bin/sh

git clone -b master https://github.com/beyond-blockchain/libbbcsig.git libs
cd libs
sh prepare.sh

cd lib
if [ -f libbbcsig.dylib ]; then
  cp libbbcsig.dylib ../../bbc1/core/
elif [ -f libbbcsig.so ]; then
  cp libbbcsig.so ../../bbc1/core/
fi
