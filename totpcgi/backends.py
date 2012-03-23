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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
import os
import logging
import totpcgi

from fcntl import flock, LOCK_EX, LOCK_UN


logger = logging.getLogger('totpcgi')

class GAStateBackend:
    def __init__(self):
        pass

    def get_user_state(self, user):
        pass

    def update_user_state(self, user, state):
        pass

    def _remove_user_state(self, user):
        pass

class GASecretBackend:
    def __init__(self):
        pass

    def get_user_secret(self, user):
        pass

class GASecretBackendFile(GASecretBackend):
    def __init__(self, secrets_dir):
        GASecretBackend.__init__(self)
        logger.debug('Using GASecretBackendFile')

        self.secrets_dir = secrets_dir

    def get_user_secret(self, user):

        totp_file = os.path.join(self.secrets_dir, 'totp', user) + '.totp'
        logger.debug('Examining user secret file: %s' % totp_file)

        if not os.access(totp_file, os.R_OK):
            raise totpcgi.UserNotFound('%s.totp does not exist or is not readable' % user)

        fh = open(totp_file, 'r')

        # secret is always the first entry
        secret = fh.readline()
        secret = secret.strip()

        gaus = totpcgi.GAUserSecret(secret)

        while True:
            line = fh.readline()

            if line == '':
                break

            line = line.strip()

            if line[0] == '"':
                if line[2:12] == 'RATE_LIMIT':
                    (tries, seconds) = line[13:].split(' ')
                    gaus.rate_limit = (int(tries), int(seconds))
                    logger.debug('rate_limit=%s' % str(gaus.rate_limit))

                elif line[2:13] == 'WINDOW_SIZE':
                    window_size = int(line[14:])
                    if window_size > 0 and window_size < 3:
                        window_size = 3
                    gaus.window_size = window_size

                    logger.debug('window_size=%s' % window_size)

            # Scratch code tokens are 8-digit
            elif len(line) == 8:
                try:
                    gaus.scratch_tokens.append(int(line))
                    logger.debug('Found a scratch-code token, adding it')
                except ValueError:
                    logger.debug('Non-numeric scratch token found')
                    # don't fail, just pretend we didn't see it
                    continue
        fh.close()

        # Make sure that we have a window_size defined
        # The topt configuration many not have had one, if not we need
        # to make sure we set it to the default of 3
        if not hasattr(gaus, 'window_size'):
                gaus.window_size = 3

        return gaus

    def get_user_hashcode(self, user):
        # The format is basically /etc/shadow, except we ignore anything
        # past the first 2 entries. We return the hashed code that we'll need
        # to compare.
        pincode_file = os.path.join(self.secrets_dir, 'pincodes')
        if not os.access(pincode_file, os.R_OK):
            raise totpcgi.UserNotFound('pincodes file not found!')

        # Check if we have a compiled version first
        logger.debug('Checking if there is a pincodes.db')
        pincode_db_file = os.path.join(self.secrets_dir, 'pincodes.db')

        if os.access(pincode_db_file, os.R_OK):
            logger.debug('Found pincodes.db. Comparing mtime with pincodes')
            dbmtime = os.stat(pincode_db_file).st_mtime
            ptmtime = os.stat(pincode_file).st_mtime

            logger.debug('dbmtime=%s' % dbmtime)
            logger.debug('ptmtime=%s' % ptmtime)

            if dbmtime >= ptmtime:
                logger.debug('.db mtime greater, will use the db')

                import anydbm
                db = anydbm.open(pincode_db_file, 'r')

                if user in db.keys():
                    logger.debug('Found %s in the .db. Returning' % user)
                    hashcode = db[user]
                    db.close()
                    return hashcode

                logger.debug('%s not in .db. Falling back to plaintext.')
            else:
                logger.debug('.db is stale! Falling back to plaintext.')

        logger.debug('Reading pincode file: %s' % pincode_file)

        fh = open(pincode_file, 'r')

        hashcode = None
        
        while True:
            line = fh.readline()
            
            if line == '':
                break

            if line.find(':') == -1:
                continue

            parts = line.split(':')
            if parts[0] == user:
                logger.debug('Found user %s' % user)
                hashcode = parts[1]
                break

        if hashcode is None:
            raise totpcgi.UserPincodeError('Pincode not found for user %s' % user)
            
        return hashcode

class GAStateBackendFile(GAStateBackend):
    def __init__(self, state_dir):
        GAStateBackend.__init__(self)
        logger.debug('Using GAStateBackendFile')

        self.state_dir = state_dir
        self.fhs = {}

    def get_user_state(self, user):
        state = totpcgi.GAUserState()

        import json

        # load the state file and keep it locked while we do verification
        state_file = os.path.join(self.state_dir, user) + '.json'
        logger.debug('Loading user state from: %s' % state_file)
        
        # Don't let anyone but ourselves see the contents of the state file
        os.umask(0077)

        # we exclusive-lock the file to prevent race conditions resulting
        # in potential token reuse.
        if os.access(state_file, os.R_OK):
            logger.debug('%s exists, opening r+' % state_file)
            fh = open(state_file, 'r+')
            logger.debug('Locking state file for user %s' % user)
            flock(fh, LOCK_EX)
            try:
                js = json.load(fh)

                logger.debug('loaded state=%s' % js)

                state.fail_timestamps     = js['fail_timestamps']
                state.success_timestamps  = js['success_timestamps']
                state.used_scratch_tokens = js['used_scratch_tokens']

            except:
                # We fail out of caution, though if someone wanted to 
                # screw things up, they could have done so without making
                # the file un-parseable by json -- all they need to do is to
                # erase the file.
                logger.debug('Unlocking state file for user %s' % user)
                flock(fh, LOCK_UN)
                raise totpcgi.UserStateError(
                        'Error parsing the state file for: %s' % user)

            fh.seek(0)
        else:
            logger.debug('%s does not exist, opening w' % state_file)
            fh = open(state_file, 'w')
            logger.debug('Locking state file for user %s' % user)
            flock(fh, LOCK_EX)


        # The following condition should never happen, in theory,
        # because we have an exclusive lock on that file. If it does, 
        # things have broken somewhere (probably locking is broken).
        if user not in self.fhs.keys():
            self.fhs[user] = fh

        return state

    def update_user_state(self, user, state):
        if user not in self.fhs.keys():
            raise totpcgi.UserStateError("%s's state FH has gone away!" % user)

        import json

        fh = self.fhs[user]

        logger.debug('fh.name=%s' % fh.name)

        js = {
            'fail_timestamps'     : state.fail_timestamps,
            'success_timestamps'  : state.success_timestamps,
            'used_scratch_tokens' : state.used_scratch_tokens
        }

        logger.debug('saving state=%s' % js)

        logger.debug('Saving new state for user %s' % user)
        json.dump(js, fh, indent=4)
        fh.truncate()

        logger.debug('Unlocking state file for user %s' % user)
        flock(fh, LOCK_UN)
        fh.close()

        del self.fhs[user]

        logger.debug('fhs=%s' % self.fhs)

    def _remove_user_state(self, user):
        # this should ONLY be used by test.py
        state_file = os.path.join(self.state_dir, '%s.json' % user)
        if os.access(state_file, os.R_OK):
            os.unlink(state_file)
            logger.debug('Removed user state file: %s' % state_file)


class GAStateBackendPostgresql(GAStateBackend):
    def __init__(self, connect_string):
        GAStateBackend.__init__(self)
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


