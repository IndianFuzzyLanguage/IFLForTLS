#!/bin/bash

i=0
while true
do
    valgrind --tool=memcheck --leak-check=full --log-file=val.txt ./bin/tserver
done
