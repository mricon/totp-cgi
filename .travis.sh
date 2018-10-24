#!/bin/bash
TEST_FLAGS=''
if [ $TRAVIS_PYTHON_VERSION == '3.6' ]; then
    TEST_FLAGS='-v --locals'
fi

echo "Running File backend tests"
python test.py $TEST_FLAGS
E_FILE=$?
echo -en 'travis_fold:start:File_backend\\r'
cat test.log
echo -en 'travis_fold:end:File_backend\\r'

rm -f test.log

echo "Running MySQL backend tests"
mysql -e 'CREATE DATABASE totpcgi;'
mysql totpcgi < contrib/mysql.sql
mysql_connect_host='localhost' \
    mysql_connect_db='totpcgi' \
    mysql_connect_user='travis' \
    mysql_connect_password='' \
    python test.py $TEST_FLAGS
E_MYSQL=$?
echo -en 'travis_fold:start:MySQL_backend\\r'
cat test.log
echo -en 'travis_fold:end:MySQL_backend\\r'

rm -f test.log

echo "Running PostgreSQL backend tests"
psql -U postgres -c 'create database totpcgi;'
psql -U postgres -d totpcgi -a -f contrib/postgres.sql
pg_connect_string='postgresql://localhost/totpcgi' \
    python test.py $TEST_FLAGS
E_PSQL=$?
echo -en 'travis_fold:start:PostgreSQL_backend\\r'
cat test.log
echo -en 'travis_fold:end:PostgreSQL_backend\\r'

if [ $E_FILE -gt 0 -o $E_MYSQL -gt 0 -o $E_PSQL -gt 0]; then
    exit 1
fi
