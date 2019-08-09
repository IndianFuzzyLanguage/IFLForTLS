#!/bin/bash

DEPENDENCY_DIR='dependency'
submodules=('IFL' 'openssl_master')

git submodule init
git submodule update
for dep in "${submodules[@]}"
do
    cd ${DEPENDENCY_DIR}/${dep}
    git checkout master
    git pull origin master
    cd -
done
