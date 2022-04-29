#!/bin/bash

DIR="$( cd "$( dirname "$0"  )" && pwd  )"
cd $DIR/Python-3.10.0

if [ ! -f "configure" ]; then
./configure --prefix=${DIR}/python-installed --with-pydebug
fi

make && make install
cd ../

cp -f detect.sh ${DIR}/python-installed/
