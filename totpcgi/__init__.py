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
import time
import pyotp
import logging
import exceptions
import re

logger = logging.getLogger('totpcgi')

SANE_USERNAME_RE = re.compile(r'([\w\.@=+_-]+)')

class UserNotFound(exceptions.Exception):
    def __init__(self, message):
        exceptions.Exception.__init__(self, message)
        logger.debug('!UserNotFound: %s' % message)

class UserSecretError(exceptions.Exception):
    def __init__(self, message):
        exceptions.Exception.__init__(self, message)
        logger.debug('!UserSecretError: %s' % message)

class UserStateError(exceptions.Exception):
    def __init__(self, message):
        exceptions.Exception.__init__(self, message)
        logger.debug('!UserStateError: %s' % message)

class UserPincodeError(exceptions.Exception):
    def __init__(self, message):
        exceptions.Exception.__init__(self, message)
        logger.debug('!UserPincodeError: %s' % message)

class VerifyFailed(exceptions.Exception):
    def __init__(self, message):
        exceptions.Exception.__init__(self, message)
        logger.debug('!VerifyFailed: %s' % message)

class GAUserState:
    def __init__(self):
        self.fail_timestamps     = []
        self.success_timestamps  = []
        self.used_scratch_tokens = []

class GAUserSecret:
    def __init__(self, secret):
        # This should immediately tell us if there are problems with the
        # secret as read from the file.
        try:
            self.totp = pyotp.TOTP(secret)

            self.token     = self.totp.now()
            self.timestamp = int(time.time())

        except Exception, ex:
            raise UserSecretError('Failed to generate totp: %s' % str(ex))

        self.rate_limit     = (3, 30)
        self.window_wize    = 0
        self.scratch_tokens = []

    def get_token_at(self, timestamp):
        return self.totp.at(timestamp)

class GAUser:
    def __init__(self, user, backends):

        mo = SANE_USERNAME_RE.match(user)
        if not mo or mo.group(1) != user:
            raise VerifyFailed('Username contains invalid characters')

        self.user   = user
        self.secret = backends.secret_backend.get_user_secret(user)
        
        self.backends = backends

    def verify_pincode(self, pincode):
        return self.backends.pincode_backend.verify_user_pincode(self.user, pincode)

    def verify_token(self, token):
        state = self.backends.state_backend.get_user_state(self.user)
        
        new_state = GAUserState()

        used_tokens = []

        for timestamp in state.success_timestamps:
            # trim any timestamps that are older than (30s + WINDOW_SIZE)
            cutoff = self.secret.timestamp-(30+(self.secret.window_size*10))

            if timestamp < cutoff:
                continue

            at_token = self.secret.get_token_at(timestamp)

            if at_token not in used_tokens:
                used_tokens.append(at_token)

            new_state.success_timestamps.append(timestamp)

        new_state.used_scratch_tokens = state.used_scratch_tokens

        logger.debug('used_tokens=%s' % used_tokens)

        # are you being rate-limited right now?
        for timestamp in state.fail_timestamps:
            # trim any timestamps that are too old to consider
            cutoff = self.secret.timestamp-(30+self.secret.rate_limit[1])
            if timestamp < cutoff:
                continue

            new_state.fail_timestamps.append(timestamp)

        used_timestamp = self.secret.timestamp
        used_token     = self.secret.token
            
        if len(new_state.fail_timestamps) >= self.secret.rate_limit[0]:
            success = (False, 'Rate-limit reached, please try again later')

        else:
            # Is this token valid at all?
            if len(str(token)) > 8:
                success = (False, 'Token is too long')
            else:
                try:
                    token = int(token)
                except ValueError:
                    success = (False, 'Token is not an integer')
                    token = -1

                # Is this a scratch-code token?
                if token > 999999:
                    logger.debug('A scratch-code token is used')

                    # has it been used before?
                    if token in state.used_scratch_tokens:
                        success = (False, 'Scratch-token already used once')
                    elif token not in self.secret.scratch_tokens:
                        success = (False, 'Not a valid scratch-token')
                    else:
                        success = (True, 'Scratch-token used')
                        new_state.used_scratch_tokens.append(token)

                elif token >= 0:
                    logger.debug('A regular token is used')

                    # has it been used before?
                    if token in used_tokens:
                        success = (False, 'Token has already been used once')
                    elif token == self.secret.token:
                        success = (True, 'Valid token used')
                    else:
                        # not a valid token right now
                        # This can stand being refactored, eh?
                        success = (False, 'Not a valid token')
                        if self.secret.window_size > 0:
                            # okay, let's try within the window_size
                            start = self.secret.timestamp-(self.secret.window_size*10)
                            end   = self.secret.timestamp+(self.secret.window_size*10)
                            for timestamp in xrange(start, end, 10):
                                at_token = self.secret.get_token_at(timestamp)
                                if at_token == token:
                                    used_timestamp = timestamp
                                    used_token = token
                                    success = (True, 
                                        'Valid token within window size used')
                                    break

            # Adjust state accordingly
            if success[0] == True:
                new_state.success_timestamps.append(used_timestamp)
            else:
                new_state.fail_timestamps.append(used_timestamp)

        self.backends.state_backend.update_user_state(self.user, new_state)

        logger.debug('success=%s' % str(success))

        if success[0] == False:
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
                itoken = int(token)
                # is it among user's valid scratch tokens?
                if itoken in user.secret.scratch_tokens:
                    if self.require_pincode:
                        raise UserPincodeError('Pincode is required')
                    # okay, proceed
                    return user.verify_token(token)
                else:
                    logger.debug('8-digits, but not a valid scratch-token')
                    logger.debug('Will obediently assume 2-digit pincode')
            except ValueError:
                logger.debug('8-char token used, but is not an int')
                logger.debug('Will obediently assume 2-letter pincode')
        
        if len(token) > 8:
            # are last 8 chars digits?
            try:
                itoken = int(token[-8:])
                # is it a valid scratch-token?
                if itoken in user.secret.scratch_tokens:
                    logger.debug('Looks like pincode+8-digit scratch code')

                    pincode   = token[:-8]
                    tokencode = token[-8:]

                    user.verify_pincode(pincode)
                    return user.verify_token(tokencode)

            except ValueError:
                pass

        logger.debug('Will treat as pincode+6-digit token')

        pincode   = token[:-6]
        tokencode = token[-6:]

        user.verify_pincode(pincode)

        return user.verify_token(tokencode)

