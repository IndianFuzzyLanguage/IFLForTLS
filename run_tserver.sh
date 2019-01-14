#!/bin/bash

valgrind --tool=memcheck --leak-check=full --log-file=val.txt ./bin/tserver
