#!/bin/bash
TEST_FLAGS=''
if [ $TRAVIS_PYTHON_VERSION == '3.6' ]; then
    TEST_FLAGS='-v --locals'
fi

echo "Running File backend tests"
python test.py $TEST_FLAGS
echo "travis_fold:start:Start File backend test.log"
cat test.log
echo "travis_fold:end:End File backend test.log"
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
echo "travis_fold:start:Start MySQL backend test.log"
cat test.log
echo "travis_fold:end:End MySQL backend test.log"
if [ "$?" != "0" ]; then
    exit $?
fi

echo "Running PostgreSQL backend tests"
psql -U postgres -c 'create database totpcgi;'
psql -U postgres -d totpcgi -a -f contrib/postgres.sql
pg_connect_string='postgresql://localhost/totpcgi' \
    python test.py $TEST_FLAGS
echo "travis_fold:start:Start PostgreSQL backend test.log"
cat test.log
echo "travis_fold:end:End PostgreSQL backend test.log"
if [ "$?" != "0" ]; then
    exit $?
fi
