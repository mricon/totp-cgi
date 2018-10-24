#!/bin/bash
TEST_FLAGS=''
[[ $TRAVIS_PYTHON_VERSION == '3.6' ]] && TEST_FLAGS='-v --locals'

echo "Running File backend tests"
python test.py $TEST_FLAGS
[[ "$?" != "0" ]] && exit $?

echo "Running MySQL backend tests"
mysql -u root < contrib/mysql.sql
mysql_connect_host='localhost' \
    mysql_connect_db='totpcgi' \
    mysql_connect_user='totpcgi_admin' \
    mysql_connect_password='bokkabokka' \
    python test.py $TEST_FLAGS
[[ "$?" != "0" ]] && exit $?
