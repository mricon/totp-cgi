# -*- coding: utf-8 -*-
##
# Copyright (C) 2012 by Konstantin Ryabitsev and contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
from __future__ import (absolute_import,
                        division,
                        print_function,
                        with_statement,
                        unicode_literals)

__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import logging
import totpcgi
import totpcgi.backends
import totpcgi.utils

import psycopg2

logger = logging.getLogger('totpcgi')

# Globally track the database connections
dbconn = {}
userids = {}


def db_connect(connect_string):
    global dbconn

    if connect_string not in dbconn or dbconn[connect_string].closed:
        dbconn[connect_string] = psycopg2.connect(connect_string)

    return dbconn[connect_string]


def get_user_id(conn, user):
    global userids

    if user in userids.keys():
        return userids[user]

    cur = conn.cursor()
    logger.debug('Checking users record for %s', user)

    cur.execute('SELECT userid FROM users WHERE username = %s', (user,))
    row = cur.fetchone()

    if row is None:
        logger.debug('No existing record for user=%s, creating', user)
        cur.execute('INSERT INTO users (username) VALUES (%s)', (user,))
        cur.execute('SELECT userid FROM users WHERE username = %s', (user,))
        row = cur.fetchone()

    userids[user] = row[0]
    return userids[user]


class GAStateBackend(totpcgi.backends.GAStateBackend):
    def __init__(self, connect_string):
        totpcgi.backends.GAStateBackend.__init__(self)
        logger.debug('Using PGSQL State backend')

        logger.debug('Establishing connection to the database')
        self.conn = db_connect(connect_string)

        logger.debug('Checking if we have the counters table')
        cur = self.conn.cursor()
        cur.execute("select exists(select * from information_schema.tables where table_name=%s)",
                    ('counters',))
        self.has_counters = cur.fetchone()[0]

        if not self.has_counters:
            logger.info('Counters table not found, assuming pre-0.6 database schema (no HOTP support)')

        self.locks = {}

    def get_user_state(self, user):

        userid = get_user_id(self.conn, user)

        state = totpcgi.GAUserState()

        logger.debug('Creating advisory lock for userid=%s', userid)
        
        cur = self.conn.cursor()
        cur.execute('SELECT pg_advisory_lock(%s)', (userid,))
        self.locks[user] = userid 

        cur.execute('''
            SELECT timestamp, success
              FROM timestamps
             WHERE userid = %s''', (userid,))

        for (timestamp, success) in cur.fetchall():
            if success:
                state.success_timestamps.append(timestamp)
            else:
                state.fail_timestamps.append(timestamp)

        cur.execute('''
            SELECT token
              FROM used_scratch_tokens
             WHERE userid = %s''', (userid,))

        for (itoken,) in cur.fetchall():
            token = str(itoken).zfill(8)
            logger.debug('Found a used scratch token: %s', token)
            state.used_scratch_tokens.append(token)

        # Now try to load counter info, if we have that table
        if self.has_counters:
            cur.execute('''
                SELECT counter
                  FROM counters
                 WHERE userid = %s''', (userid,))

            row = cur.fetchone()
            if row and row[0] >= 0:
                state.counter = row[0]

        return state

    def update_user_state(self, user, state):
        logger.debug('Writing new state for user %s', user)

        if user not in self.locks.keys():
            raise totpcgi.UserStateError("%s's pg lock has gone away!" % user)

        userid = self.locks[user]

        cur = self.conn.cursor()

        cur.execute('DELETE FROM timestamps WHERE userid=%s', (userid,))
        cur.execute('DELETE FROM used_scratch_tokens WHERE userid=%s', (userid,))

        for timestamp in state.fail_timestamps:
            cur.execute('''
                INSERT INTO timestamps (userid, success, timestamp)
                     VALUES (%s, %s, %s)''', (userid, False, timestamp))

        for timestamp in state.success_timestamps:
            cur.execute('''
                INSERT INTO timestamps (userid, success, timestamp)
                     VALUES (%s, %s, %s)''', (userid, True, timestamp))

        for token in state.used_scratch_tokens:
            cur.execute('''
                INSERT INTO used_scratch_tokens (userid, token)
                     VALUES (%s, %s)''', (userid, token))

        if state.counter >= 0 and self.has_counters:
            cur.execute('DELETE FROM counters WHERE userid=%s', (userid,))
            cur.execute('''
                INSERT INTO counters (userid, counter)
                     VALUES (%s, %s)''', (userid, state.counter))

        logger.debug('Unlocking advisory lock for userid=%s', userid)
        cur.execute('SELECT pg_advisory_unlock(%s)', (userid,))

        self.conn.commit()

        del self.locks[user]

    def delete_user_state(self, user):
        cur = self.conn.cursor()
        logger.debug('Deleting state records for user=%s', user)

        userid = get_user_id(self.conn, user)

        cur.execute('''
            DELETE FROM timestamps
                  WHERE userid=%s''' % (userid,))
        cur.execute('''
            DELETE FROM used_scratch_tokens
                  WHERE userid=%s''' % (userid,))

        if self.has_counters:
            cur.execute('''
                DELETE FROM counters
                      WHERE userid=%s''' % (userid,))

        # If there are no pincodes or secrets entries, then we may as well
        # delete the user record.
        cur.execute('SELECT True FROM pincodes WHERE userid=%s', (userid,))
        if not cur.fetchone():
            cur.execute('SELECT True FROM secrets WHERE userid=%s', (userid,))
            if not cur.fetchone():
                logger.debug('No entries left for user=%s, deleting', user)
                try:
                    cur.execute('DELETE FROM users WHERE userid=%s', (userid,))
                except psycopg2.ProgrammingError:
                    # we may not have permissions, so ignore this failure.
                    pass

        self.conn.commit()


class GASecretBackend(totpcgi.backends.GASecretBackend):
    def __init__(self, connect_string):
        totpcgi.backends.GASecretBackend.__init__(self)
        logger.debug('Using PGSQL Secrets backend')

        logger.debug('Establishing connection to the database')
        self.conn = db_connect(connect_string)

        logger.debug('Checking if we have the counters table')
        cur = self.conn.cursor()
        cur.execute("select exists(select * from information_schema.tables where table_name=%s)",
                    ('counters',))
        self.has_counters = cur.fetchone()[0]

        if not self.has_counters:
            logger.info('Counters table not found, assuming pre-0.6 database schema (no HOTP support)')

    def get_user_secret(self, user, pincode=None):
        cur = self.conn.cursor()

        logger.debug('Querying DB for user %s', user)

        cur.execute('''
            SELECT s.secret, 
                   s.rate_limit_times, 
                   s.rate_limit_seconds, 
                   s.window_size
              FROM secrets AS s 
              JOIN users AS u USING (userid)
             WHERE u.username = %s''', (user,))
        row = cur.fetchone()

        if not row:
            raise totpcgi.UserNotFound('no secrets record for %s' % user)

        (secret, rate_limit_times, rate_limit_seconds, window_size) = row

        using_encrypted_secret = False
        if secret.find('aes256+hmac256') == 0 and pincode is not None:
            secret = totpcgi.utils.decrypt_secret(secret, pincode)
            using_encrypted_secret = True
        
        gaus = totpcgi.GAUserSecret(secret)
        if rate_limit_times is not None and rate_limit_seconds is not None:
            gaus.rate_limit = (rate_limit_times, rate_limit_seconds)

        if window_size is not None:
            gaus.window_size = window_size

        logger.debug('Querying DB for counter info for %s', user)
        # Now try to load counter info, if we have that table
        if self.has_counters:
            cur.execute('''
                SELECT c.counter
                  FROM counters AS c
                  JOIN users AS u USING (userid)
                 WHERE u.username = %s''', (user,))

            row = cur.fetchone()
            if row:
                gaus.set_hotp(row[0])

        # Not loading scratch tokens if using encrypted secret
        if using_encrypted_secret:
            return gaus

        logger.debug('Querying DB for scratch tokens for %s', user)

        cur.execute('''
            SELECT st.token
              FROM scratch_tokens AS st
              JOIN users AS u USING (userid)
             WHERE u.username = %s''', (user,))
        
        for (itoken,) in cur.fetchall():
            token = str(itoken).zfill(8)
            logger.debug('Adding a scratch token: %s', token)
            gaus.scratch_tokens.append(token)

        return gaus

    def save_user_secret(self, user, gaus, pincode=None):
        cur = self.conn.cursor()

        self._delete_user_secret(user)

        userid = get_user_id(self.conn, user)

        secret = gaus.otp.secret

        if pincode is not None:
            secret = totpcgi.utils.encrypt_secret(secret, pincode)

        cur.execute('''
            INSERT INTO secrets 
                        (userid, secret, rate_limit_times,
                         rate_limit_seconds, window_size)
                 VALUES (%s, %s, %s, %s, %s)''', 
                    (userid, secret, gaus.rate_limit[0], gaus.rate_limit[1], gaus.window_size))

        for token in gaus.scratch_tokens:
            cur.execute('''
                    INSERT INTO scratch_tokens
                                (userid, token)
                         VALUES (%s, %s)''', (userid, token,))

        self.conn.commit()

    def _delete_user_secret(self, user):
        userid = get_user_id(self.conn, user)

        cur = self.conn.cursor()
        cur.execute('''
            DELETE FROM secrets
                  WHERE userid=%s''', (userid,))
        cur.execute('''
            DELETE FROM scratch_tokens
                  WHERE userid=%s''', (userid,))

    def delete_user_secret(self, user):
        self._delete_user_secret(user)
        self.conn.commit()


class GAPincodeBackend(totpcgi.backends.GAPincodeBackend):
    def __init__(self, connect_string):
        totpcgi.backends.GAPincodeBackend.__init__(self)
        logger.debug('Using PGSQL Pincodes backend')

        logger.debug('Establishing connection to the database')
        self.conn = db_connect(connect_string)
        
    def verify_user_pincode(self, user, pincode):
        cur = self.conn.cursor()

        logger.debug('Querying DB for user %s', user)

        cur.execute('''
            SELECT p.pincode
              FROM pincodes AS p
              JOIN users AS u USING (userid)
             WHERE u.username = %s''', (user,))

        row = cur.fetchone()

        if not row:
            raise totpcgi.UserNotFound('no pincodes record for user %s' % user)

        (hashcode,) = row

        return self._verify_by_hashcode(pincode, hashcode)

    def _delete_user_hashcode(self, user):
        userid = get_user_id(self.conn, user)

        cur = self.conn.cursor()
        cur.execute('''
            DELETE FROM pincodes 
                  WHERE userid=%s''', (userid,))
        
    def save_user_hashcode(self, user, hashcode, makedb=False):
        self._delete_user_hashcode(user)

        userid = get_user_id(self.conn, user)

        cur = self.conn.cursor()

        cur.execute('''
            INSERT INTO pincodes
                        (userid, pincode)
                 VALUES (%s, %s)''', (userid, hashcode,))

        self.conn.commit()

    def delete_user_hashcode(self, user):
        self._delete_user_hashcode(user)
        self.conn.commit()
