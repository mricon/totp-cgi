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

import os
from fcntl import flock, LOCK_EX, LOCK_UN

class GAPincodeBackend(totpcgi.backends.GAPincodeBackend):
    def __init__(self, pincode_file):
        totpcgi.backends.GAPincodeBackend.__init__(self)
        logger.debug('Using FILE Pincode backend')

        self.pincode_file = pincode_file

    def verify_user_pincode(self, user, pincode):
        # The format is basically /etc/shadow, except we ignore anything
        # past the first 2 entries. We return the hashed code that we'll need
        # to compare.
        if not os.access(self.pincode_file, os.R_OK):
            raise totpcgi.UserNotFound('pincodes file not found!')

        # Check if we have a compiled version first
        logger.debug('Checking if there is a pincodes.db')
        pincode_db_file = self.pincode_file + '.db'

        hashcode = None

        if os.access(pincode_db_file, os.R_OK):
            logger.debug('Found pincodes.db. Comparing mtime with pincodes')
            dbmtime = os.stat(pincode_db_file).st_mtime
            ptmtime = os.stat(self.pincode_file).st_mtime

            logger.debug('dbmtime=%s' % dbmtime)
            logger.debug('ptmtime=%s' % ptmtime)

            if dbmtime >= ptmtime:
                logger.debug('.db mtime greater, will use the db')

                import anydbm
                db = anydbm.open(pincode_db_file, 'r')

                if user in db.keys():
                    logger.debug('Found %s in the .db' % user)
                    hashcode = db[user]
                    db.close()

                logger.debug('%s not in .db. Falling back to plaintext.')
            else:
                logger.debug('.db is stale! Falling back to plaintext.')

        if hashcode is None:
            logger.debug('Reading pincode file: %s' % self.pincode_file)

            fh = open(self.pincode_file, 'r')

            while True:
                line = fh.readline()
                
                if line == '':
                    break

                if line.find(':') == -1:
                    continue

                line = line.strip()

                parts = line.split(':')
                if parts[0] == user:
                    logger.debug('Found user %s' % user)
                    hashcode = parts[1]
                    break

            fh.close()

        if hashcode is None:
            raise totpcgi.UserPincodeError('Pincode not found for user %s' % user)

        return self._verify_by_hashcode(pincode, hashcode)


class GASecretBackend(totpcgi.backends.GASecretBackend):
    def __init__(self, secrets_dir):
        totpcgi.backends.GASecretBackend.__init__(self)
        logger.debug('Using FILE Secret backend')

        self.secrets_dir = secrets_dir

    def get_user_secret(self, user):

        totp_file = os.path.join(self.secrets_dir, user) + '.totp'
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
            
        return hashcode

class GAStateBackend(totpcgi.backends.GAStateBackend):
    def __init__(self, state_dir):
        totpcgi.backends.GAStateBackend.__init__(self)
        logger.debug('Using FILE State backend')

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
