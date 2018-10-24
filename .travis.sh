#!/bin/bash
TEST_FLAGS=''
if [ $TRAVIS_PYTHON_VERSION == '3.6' ]; then
    TEST_FLAGS='-v --locals'
fi

echo "Running File backend tests"
python test.py $TEST_FLAGS
cat test.log
if [ "$?" != "0" ]; then
    exit $?
fi

rm -f test.log

echo "Running MySQL backend tests"
mysql -e 'CREATE DATABASE totpcgi;'
mysql totpcgi < contrib/mysql.sql
mysql_connect_host='localhost' \
    mysql_connect_db='totpcgi' \
    mysql_connect_user='travis' \
    mysql_connect_password='' \
    python test.py $TEST_FLAGS
cat test.log
if [ "$?" != "0" ]; then
    exit $?
fi
