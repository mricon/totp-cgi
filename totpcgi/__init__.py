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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
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

import time
import pyotp
import logging
import re

logger = logging.getLogger('totpcgi')

SANE_USERNAME_RE = re.compile(r'([\w.@=+_-]+)')


class UserNotFound(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!UserNotFound: %s', message)


class UserSecretError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!UserSecretError: %s', message)


class UserStateError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!UserStateError: %s', message)


class UserPincodeError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!UserPincodeError: %s', message)


class VerifyFailed(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!VerifyFailed: %s', message)


class SaveFailed(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!SaveFailed: %s', message)


class DeleteFailed(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!DeleteFailed: %s', message)


class GAUserState:
    def __init__(self):
        self.fail_timestamps = []
        self.success_timestamps = []
        self.used_scratch_tokens = []
        self.counter = -1


class GAUserSecret:
    def __init__(self, secret):
        self.timestamp = int(time.time())
        self.rate_limit = (3, 30)
        self.window_size = 3
        self.scratch_tokens = []
        self.counter = -1

        # This should immediately tell us if there are problems with the
        # secret as read from the file.
        try:
            self.otp = pyotp.TOTP(secret)
            self.get_totp_token()

        except Exception as ex:
            raise UserSecretError('Failed to generate totp: %s' % str(ex))

    def set_hotp(self, counter):
        if isinstance(self.otp, pyotp.totp.TOTP):
            logger.info('Switching into HOTP mode')
            self.otp = pyotp.HOTP(self.otp.secret)

        self.counter = counter

    def is_hotp(self):
        return self.counter >= 0

    def get_totp_token(self):
        return self.otp.at(self.timestamp)

    def get_token_at(self, count):
        # same method for both TOTP and HOTP, except for TOTP the count is the timestamp
        return self.otp.at(count)

    def verify_scratch_token(self, token):
        logger.debug(self.scratch_tokens)
        return token in self.scratch_tokens

    def verify_token(self, token):
        if self.counter < 0:
            logger.debug('Verifying as TOTP')
            current = self.get_totp_token()
            if token == current:
                return True, 'Valid TOTP token used'
            else:
                # not a valid token right now
                if self.window_size > 0:
                    # okay, let's try within the window_size
                    start = self.timestamp-(self.window_size*10)
                    end = self.timestamp+(self.window_size*10)+1
                    logger.debug('start=%s, end=%s', start, end)

                    for timestamp in range(start, end, 10):
                        at_token = self.get_token_at(timestamp)
                        logger.debug('timestamp=%s, at_token=%s', timestamp, at_token)
                        if at_token == token:
                            self.timestamp = timestamp
                            return True, 'Valid TOTP token within window size used'

            return False, 'TOTP token failed to verify'

        else:
            logger.debug('Verifying as HOTP')
            current = self.get_token_at(self.counter)
            if token == current:
                self.counter += 1
                logger.info('Incremented counter to %s', self.counter)
                return True, 'Valid HOTP token used'
            else:
                if self.window_size > 0:
                    # okay, let's try next window_size tokens
                    for at_count in range(self.counter, self.counter+self.window_size+1, 1):
                        at_token = self.get_token_at(at_count)
                        logger.debug('Trying with counter=%s; at_token=%s', at_count, at_token)
                        if at_token == token:
                            logger.info('Incremented counter by %s ticks to %s',
                                        at_count-self.counter, at_count+1)
                            self.counter = at_count+1
                            return True, 'Valid HOTP token within window size used'

            return False, 'HOTP token failed to verify'


class GAUser:
    def __init__(self, user, backends):

        mo = SANE_USERNAME_RE.match(user)
        if not mo or mo.group(1) != user:
            raise VerifyFailed('Username contains invalid characters')

        self.user = user
        self.backends = backends

    def verify_pincode(self, pincode):
        return self.backends.pincode_backend.verify_user_pincode(self.user, pincode)

    def verify_token(self, token, pincode=None):
        logger.debug('token=%s', token)
        success = (False, 'Verification failed')

        try:
            secret = self.backends.secret_backend.get_user_secret(self.user, pincode)
        except UserSecretError as ex:
            logger.debug('Failed to obtain user secret: %s', ex)
            logger.debug('Marking failed timestamp and returning failure')
            state = self.backends.state_backend.get_user_state(self.user)
            # Since we were not able to obtain the secret object, we bluntly
            # invalidate the past 10 timestamps
            now = int(time.time())
            for timestamp in range(now, now-300, -30):
                state.fail_timestamps.append(timestamp)
            self.backends.state_backend.update_user_state(self.user, state)
            raise ex

        state = self.backends.state_backend.get_user_state(self.user)
        new_state = GAUserState()

        # grab the counter from the state and modify user secret with latest counter info
        logger.debug('state.counter=%s, secret.counter=%s', state.counter, secret.counter)
        if state.counter > secret.counter:
            secret.set_hotp(state.counter)

        used_tokens = []

        new_state.used_scratch_tokens = state.used_scratch_tokens

        # We only track used_tokens in TOTP mode, so we don't care to track success_timestamps
        # when we're using counters instead.
        if not secret.is_hotp():

            for timestamp in state.success_timestamps:
                # trim any timestamps that are older than (30s + WINDOW_SIZE)
                cutoff = secret.timestamp-(30+(secret.window_size*10))

                if timestamp < cutoff:
                    continue

                at_token = secret.get_token_at(timestamp)

                if at_token not in used_tokens:
                    used_tokens.append(at_token)

                new_state.success_timestamps.append(timestamp)

        # are you being rate-limited right now?
        for timestamp in state.fail_timestamps:
            # trim any timestamps that are too old to consider
            cutoff = secret.timestamp-(30+secret.rate_limit[1])
            if timestamp < cutoff:
                continue

            if not secret.is_hotp():
                at_token = secret.get_token_at(timestamp)

                if at_token not in used_tokens:
                    used_tokens.append(at_token)

            new_state.fail_timestamps.append(timestamp)

        logger.debug('used_tokens=%s', used_tokens)

        if len(new_state.fail_timestamps) >= secret.rate_limit[0]:
            success = (False, 'Rate-limit reached, please try again later')

        else:
            try:
                itoken = int(token)
            except ValueError:
                success = (False, 'Token is not an integer')
                itoken = -1

            if len(str(token)) >= 8 and itoken >= 0:
                # Try to verify as a scratch token
                # has it been used before?
                if token in state.used_scratch_tokens:
                    success = (False, 'Scratch-token already used once')
                elif not secret.verify_scratch_token(token):
                    # we get out early, without updating state, since we
                    # will retry this as a pincode+6-digit token and the
                    # failure will be recorded at that step.
                    self.backends.state_backend.update_user_state(
                        self.user, state)
                    raise VerifyFailed('Not a valid scratch-token')
                else:
                    success = (True, 'Scratch-token used')
                    new_state.used_scratch_tokens.append(token)

            elif itoken >= 0:
                logger.debug('A regular token is used')

                # has it been used before?
                if not secret.is_hotp() and token in used_tokens:
                    success = (False, 'Token has already been used once')
                else:
                    success = secret.verify_token(token)

            # Adjust state accordingly
            if success[0] is True:
                new_state.success_timestamps.append(secret.timestamp)
            else:
                # Add all timestamps that are within the back-window
                for ts in range(secret.timestamp, secret.timestamp-(secret.window_size*10), -30):
                    logger.debug('Adding timestamp to failed: %s', ts)
                    new_state.fail_timestamps.append(ts)

        new_state.counter = secret.counter
        self.backends.state_backend.update_user_state(self.user, new_state)

        logger.debug('success=%s', str(success))

        if success[0] is False:
            raise VerifyFailed(success[1])

        return success[1]


class GoogleAuthenticator:

    def __init__(self, backends, require_pincode=False):
        self.backends = backends
        self.require_pincode = require_pincode

    def verify_user_token(self, user, token):
        user = GAUser(user, self.backends)
        # let's figure out if it's:
        #  1. regular 6-digit token
        #  2. 8-digit scratch-code
        #  3. pincode+6-digit token
        #  4. pincode+8-digit scratch-code

        if len(token) <= 6:
            logger.debug('Regular 6-digit token used')
            if self.require_pincode:
                raise UserPincodeError('Pincode is required')

            return user.verify_token(token)

        if len(token) == 8:
            # is it a valid integer?
            try:
                int(token)
                # let's try to load it as an 8-digit token
                try:
                    logger.debug('Trying to verify %s as an 8-digit scratch-token', token)

                    success = user.verify_token(token)
                    if self.require_pincode:
                        raise UserPincodeError('Pincode is required')
                    return success

                except VerifyFailed:
                    logger.debug('8-digits, but not a valid scratch-token')

            except ValueError:
                logger.debug('8-char token used, but is not an int')
        
        # Let's try to verify as a pincode + 6-digit 
        pincode = token[:-6]
        tokencode = token[-6:]

        try:
            user.verify_pincode(pincode)
            return user.verify_token(tokencode, pincode)
        except UserPincodeError:
            logger.debug('Did not succeed treating as pincode+6-digit')

        logger.debug('Trying to verify as pincode + 8-digit scratch code')

        pincode = token[:-8]
        tokencode = token[-8:]

        try:
            user.verify_pincode(pincode)
        except UserPincodeError as ex:
            # Run it anyway to record the timestamp as used
            try:
                user.verify_token(tokencode, pincode)
            except VerifyFailed:
                # We expect it to fail here, but this is not the error code
                # we want to return to the app.
                pass

            raise ex

        return user.verify_token(tokencode, pincode)
