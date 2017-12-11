#!/bin/bash

rm -rf .bbc1*
echo > result.txt

for f in test_*.py
do
    echo "**** start test of ${f} ****"
    echo "** ${f}       [dummy string: passed seconds]" >> result.txt
    pytest ${f} >> result.txt
done

grep passed result.txt | grep seconds
