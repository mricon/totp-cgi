#!/bin/bash
TEST_FLAGS=''
if [ $TRAVIS_PYTHON_VERSION == '3.6' -o $TRAVIS_PYTHON_VERSION == '3.7' ]; then
    TEST_FLAGS='-v --locals'
fi

echo "Running File backend tests"
python test.py $TEST_FLAGS
E_FILE=$?
echo "Exited with $E_FILE"
echo 'travis_fold:start:File_backend'
cat test.log
echo 'travis_fold:end:File_backend'
rm -f test.log

echo
echo "Running MySQL backend tests"
mysql -e 'CREATE DATABASE totpcgi;'
mysql totpcgi < contrib/mysql.sql
mysql_connect_host='localhost' \
    mysql_connect_db='totpcgi' \
    mysql_connect_user='travis' \
    mysql_connect_password='' \
    python test.py $TEST_FLAGS
E_MYSQL=$?
echo "Exited with $E_MYSQL"
echo 'travis_fold:start:MySQL_backend'
cat test.log
echo 'travis_fold:end:MySQL_backend'
rm -f test.log

echo
echo "Running PostgreSQL backend tests"
psql -U postgres -c 'create database totpcgi;'
psql -U postgres -d totpcgi -f contrib/postgres.sql
pg_connect_string='postgresql://localhost/totpcgi' \
    python test.py $TEST_FLAGS
E_PSQL=$?
echo "Exited with $E_PSQL"
echo 'travis_fold:start:PostgreSQL_backend'
cat test.log
echo 'travis_fold:end:PostgreSQL_backend'
rm -f test.log

echo
echo "Running LDAP backend tests"
mkdir /tmp/slapd
slapd -f test/ldap/slapd.conf -h ldap://localhost:3389 &
sleep 3
ldapadd -h localhost:3389 -D cn=admin,dc=example,dc=com -w test -f test/ldap/base.ldif
ldapadd -h localhost:3389 -D cn=admin,dc=example,dc=com -w test -f test/ldap/valid.ldif
ldap_url='ldap://localhost:3389' \
    ldap_dn='cn=$username,dc=example,dc=com' \
    ldap_cacert='' \
    ldap_user='valid' \
    ldap_password='wakkawakka' \
    python test.py $TEST_FLAGS
E_LDAP=$?
echo "Exited with $E_LDAP"
echo 'travis_fold:start:LDAP_backend'
cat test.log
echo 'travis_fold:end:LDAP_backend'

if [ $E_FILE -gt 0 -o $E_MYSQL -gt 0 -o $E_PSQL -gt 0 -o $E_LDAP -gt 0 ]; then
    exit 1
fi
