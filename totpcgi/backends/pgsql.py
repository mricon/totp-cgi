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
from __future__ import absolute_import

import logging
import totpcgi
import totpcgi.backends

logger = logging.getLogger('totpcgi')

class GAStateBackend(totpcgi.backends.GAStateBackend):
    def __init__(self, connect_string):
        totpcgi.backends.GAStateBackend.__init__(self)
        logger.debug('Using GAStateBackendPostgresql')

        import psycopg2
        conn = psycopg2.connect(connect_string)

        logger.debug('Establishing connection to the database')
        self.conn = conn

        self.locks = {}

    def get_user_state(self, user):
        cur = self.conn.cursor()

        logger.debug('Looking up state info for user %s' % user)

        cur.execute('SELECT userid FROM users WHERE username = %s', (user,))
        row = cur.fetchone()

        state = totpcgi.GAUserState()

        if row is not None:
            logger.debug('Existing record found for user=%s, loading' % user)

            (userid,) = row
            logger.debug('Creating advisory lock for userid=%s' % userid)
            
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

            for (token,) in cur.fetchall():
                state.used_scratch_tokens.append(token)

        else:
            logger.debug('No existing record for user=%s, creating' % user)

            cur.execute('INSERT INTO users (username) VALUES (%s)', (user,))

            cur.execute('SELECT userid FROM users WHERE username = %s', (user,))
            row = cur.fetchone()

            (userid,) = row
            logger.debug('Creating advisory lock for userid=%s' % userid)
            
            cur.execute('SELECT pg_advisory_lock(%s)', (userid,))
            self.locks[user] = userid 

        return state

    def update_user_state(self, user, state):
        logger.debug('Writing new state for user %s' % user)

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

        logger.debug('Unlocking advisory lock for userid=%s' % userid)
        cur.execute('SELECT pg_advisory_unlock(%s)', (userid,))

        self.conn.commit()

        del self.locks[user]

    def _remove_user_state(self, user):
        cur = self.conn.cursor()
        logger.debug('Deleting state records for user=%s' % user)

        # should cascade correctly
        cur.execute('DELETE FROM users WHERE username=%s', (user,))
        self.conn.commit()

class GASecretBackend(totpcgi.backends.GASecretBackend):
    def __init__(self):
        raise totpcgi.backends.BackendNotSupported(
                'Secrets backend not supported by pgsql backend engine')

    def get_user_secret(self, user):
        pass

class GAPincodeBackend:
    def __init__(self):
        raise totpcgi.backends.BackendNotSupported(
                'Pincode backend not supported by pgsql backend engine')

    def verify_user_pincode(self, user, pincode):
        pass
