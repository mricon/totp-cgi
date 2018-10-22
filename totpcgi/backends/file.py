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
import totpcgi.utils

import os
from fcntl import lockf, LOCK_EX, LOCK_UN, LOCK_SH

logger = logging.getLogger('totpcgi')


class GAPincodeBackend(totpcgi.backends.GAPincodeBackend):
    def __init__(self, pincode_file):
        totpcgi.backends.GAPincodeBackend.__init__(self)
        logger.debug('Using FILE Pincode backend')

        self.pincode_file = pincode_file

    def _get_all_hashcodes(self):
        hashcodes = {}

        try:
            fh = open(self.pincode_file, 'r')
            lockf(fh, LOCK_SH)

            while True:
                line = fh.readline()
                if not line:
                    break

                if line.find(':') == -1:
                    continue

                line = line.strip()

                parts = line.split(':')
                logger.debug('user=%s, hashcode=%s', parts[0], parts[1])
                hashcodes[parts[0]] = parts[1]

            logger.debug('Read %s entries from %s',
                         len(hashcodes), self.pincode_file)

            lockf(fh, LOCK_UN)
            fh.close()

        except IOError:
            logger.debug('%s could not be open for reading', self.pincode_file)

        return hashcodes

    def verify_user_pincode(self, user, pincode):
        # The format is basically /etc/shadow, except we ignore anything
        # past the first 2 entries. We return the hashed code that we'll need
        # to compare.
        if not os.access(self.pincode_file, os.R_OK):
            raise totpcgi.UserNotFound('pincodes file not found!')

        logger.debug('Reading pincode file: %s', self.pincode_file)

        hashcodes = self._get_all_hashcodes()

        try:
            hashcode = hashcodes[user]
        except KeyError:
            raise totpcgi.UserPincodeError('Pincode not found for user %s' % user)

        return self._verify_by_hashcode(pincode, hashcode)

    def save_user_hashcode(self, user, hashcode):
        hashcodes = self._get_all_hashcodes()

        if hashcode is None:
            logger.debug('Hashcode is None, deleting %s', user)
            try:
                hashcodes.pop(user)
            except KeyError:
                # wasn't there anyway
                pass

        else:
            logger.debug('Setting new hashcode: %s:%s', user, hashcode)
            hashcodes[user] = hashcode

        # Bubble up any write errors up the chain
        with open(self.pincode_file, 'w') as fh:
            lockf(fh, LOCK_EX)
            for user, hashcode in hashcodes.items():
                fh.write('%s:%s\n' % (user, hashcode))

            lockf(fh, LOCK_UN)

    def delete_user_hashcode(self, user):
        self.save_user_hashcode(user, None)


class GASecretBackend(totpcgi.backends.GASecretBackend):
    def __init__(self, secrets_dir):
        totpcgi.backends.GASecretBackend.__init__(self)
        logger.debug('Using FILE Secret backend')

        self.secrets_dir = secrets_dir

    def get_user_secret(self, user, pincode=None):

        totp_file = os.path.join(self.secrets_dir, user) + '.totp'
        logger.debug('Examining user secret file: %s', totp_file)

        if not os.access(totp_file, os.R_OK):
            raise totpcgi.UserNotFound('%s.totp does not exist or is not readable' % user)

        with open(totp_file, 'r') as fh:
            lockf(fh, LOCK_SH)

            # secret is always the first entry
            secret = fh.readline()
            secret = secret.strip()

            using_encrypted_secret = False
            if secret.find('aes256+hmac256') == 0:
                using_encrypted_secret = True
                if pincode is not None:
                    secret = totpcgi.utils.decrypt_secret(secret, pincode)
                else:
                    raise totpcgi.UserSecretError('Secret is encrypted, but no pincode provided')

            gaus = totpcgi.GAUserSecret(secret)

            while True:
                line = fh.readline()

                if line == '':
                    break

                line = line.strip()

                if len(line) and line[0] == '"':
                    if line[2:12] == 'RATE_LIMIT':
                        (tries, seconds) = line[13:].split(' ')
                        gaus.rate_limit = (int(tries), int(seconds))
                        logger.debug('rate_limit=%s', str(gaus.rate_limit))

                    elif line[2:13] == 'WINDOW_SIZE':
                        window_size = int(line[14:])
                        if 0 < window_size < 3:
                            window_size = 3
                        gaus.window_size = window_size
                        logger.debug('window_size=%s', window_size)

                    elif line[2:14] == 'HOTP_COUNTER':
                        # This will most likely be overriden by user state, but load it up anyway,
                        # as this will trigger HOTP mode.
                        try:
                            gaus.set_hotp(int(line[15:]))
                        except ValueError:
                            gaus.set_hotp(0)

                        logger.debug('hotp_counter=%s', gaus.counter)

                # Scratch code tokens are 8-digit
                # We ignore scratch tokens if we're using encrypted secret
                elif len(line) == 8 and not using_encrypted_secret:
                    try:
                        gaus.scratch_tokens.append(line)
                        logger.debug('Found a scratch-code token, adding it')
                    except ValueError:
                        logger.debug('Non-numeric scratch token found')
                        # don't fail, just pretend we didn't see it
                        continue

            lockf(fh, LOCK_UN)

        # Make sure that we have a window_size defined
        # The topt configuration many not have had one, if not we need
        # to make sure we set it to the default of 3
        if not hasattr(gaus, 'window_size'):
                gaus.window_size = 3

        return gaus

    def save_user_secret(self, user, gaus, pincode=None):
        totp_file = os.path.join(self.secrets_dir, user) + '.totp'

        try:
            fh = open(totp_file, 'w')
        except IOError as ex:
            raise totpcgi.SaveFailed('%s could not be saved: %s' %
                                     (totp_file, ex))

        lockf(fh, LOCK_EX)
        secret = gaus.otp.secret

        if pincode is not None:
            secret = totpcgi.utils.encrypt_secret(secret, pincode)

        fh.write('%s\n' % secret)
        fh.write('" RATE_LIMIT %s %s\n' % gaus.rate_limit)
        fh.write('" WINDOW_SIZE %s\n' % gaus.window_size)
        if gaus.is_hotp():
            fh.write('" HOTP_COUNTER %s\n' % gaus.counter)
        else:
            fh.write('" DISALLOW_REUSE\n')
            fh.write('" TOTP_AUTH\n')

        if pincode is None:
            fh.write('\n'.join(gaus.scratch_tokens))

        lockf(fh, LOCK_UN)
        fh.close()

        logger.debug('Wrote %s', totp_file)

    def delete_user_secret(self, user):
        totp_file = os.path.join(self.secrets_dir, user) + '.totp'

        try:
            os.unlink(totp_file)
        except (OSError, IOError) as e:
            raise totpcgi.DeleteFailed('%s could not be deleted: %s' %
                                       (totp_file, e))


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
        logger.debug('Loading user state from: %s', state_file)
        
        # For totpcgiprov and totpcgi to be able to write to the same state
        # file, we have to create it world-writable. Since we have restricted
        # permissions on the parent directory (totpcgi:totpcgiprov), plus
        # selinux labels in place, this should keep this safe from tampering.
        os.umask(0000)

        # we exclusive-lock the file to prevent race conditions resulting
        # in potential token reuse.
        if os.access(state_file, os.W_OK):
            logger.debug('%s exists, opening r+', state_file)
            fh = open(state_file, 'r+')
            logger.debug('Locking state file for user %s', user)
            lockf(fh, LOCK_EX)
            try:
                js = json.load(fh)

                logger.debug('loaded state=%s', js)

                state.fail_timestamps = js['fail_timestamps']
                state.success_timestamps = js['success_timestamps']
                state.used_scratch_tokens = js['used_scratch_tokens']

                if 'counter' in js:
                    state.counter = js['counter']

            except Exception as ex:
                # We fail out of caution, though if someone wanted to 
                # screw things up, they could have done so without making
                # the file un-parseable by json -- all they need to do is to
                # erase the file.
                logger.debug('Parsing json failed with: %s', ex)
                logger.debug('Unlocking state file for user %s', user)
                lockf(fh, LOCK_UN)
                raise totpcgi.UserStateError(
                    'Error parsing the state file for: %s' % user)

            fh.seek(0)
        else:
            logger.debug('%s does not exist, opening w', state_file)
            try:
                fh = open(state_file, 'w')
            except IOError:
                raise totpcgi.UserStateError(
                    'Cannot write user state for %s, exiting.' % user)
            logger.debug('Locking state file for user %s', user)
            lockf(fh, LOCK_EX)

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

        logger.debug('fh.name=%s', fh.name)

        js = {
            'fail_timestamps': state.fail_timestamps,
            'success_timestamps': state.success_timestamps,
            'used_scratch_tokens': state.used_scratch_tokens,
            'counter': state.counter
        }

        logger.debug('saving state=%s', js)

        logger.debug('Saving new state for user %s', user)
        json.dump(js, fh, indent=4)
        fh.truncate()

        logger.debug('Unlocking state file for user %s', user)
        lockf(fh, LOCK_UN)
        fh.close()

        del self.fhs[user]

        logger.debug('fhs=%s', self.fhs)

    def delete_user_state(self, user):
        # this should ONLY be used by test.py
        state_file = os.path.join(self.state_dir, '%s.json' % user)
        if os.access(state_file, os.W_OK):
            os.unlink(state_file)
            logger.debug('Removed user state file: %s', state_file)
