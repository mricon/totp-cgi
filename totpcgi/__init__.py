#!/usr/bin/python -tt
import time
import pyotp
import os
import logging
import exceptions
import re
import json

from fcntl import flock, LOCK_EX, LOCK_UN

logger = logging.getLogger('totpcgi')

SANE_USERNAME_RE = re.compile(r'([\w\.@=+_-]+)')

class UserNotFound(exceptions.Exception):
    def __init__(self, message):
        exceptions.Exception.__init__(self, message)
        logger.debug('!UserNotFound: %s' % message)

class UserFileError(exceptions.Exception):
    def __init__(self, message):
        exceptions.Exception.__init__(self, message)
        logger.debug('!VerifyFailed: %s' % message)

class VerifyFailed(exceptions.Exception):
    def __init__(self, message):
        exceptions.Exception.__init__(self, message)
        logger.debug('!VerifyFailed: %s' % message)

class GAUser:
    def __init__(self, user, secrets_dir, status_dir):
        self.secrets_dir = secrets_dir
        self.status_dir  = status_dir

        self.user = None
        self.totp = None

        self.now_token     = None
        self.now_timestamp = None

        self.used_token     = None
        self.used_timestamp = None

        self.rate_limit  = (3, 30)
        self.window_size = 0

        self.disallow_reuse = True

        self.scratch_tokens = []

        mo = SANE_USERNAME_RE.match(user)
        if not mo or mo.group(1) != user:
            raise VerifyFailed('Username contains invalid characters')

        self.user = user

        totp_file = os.path.join(self.secrets_dir, user) + '.totp'

        logger.debug('Examining %s' % totp_file)

        if not os.access(totp_file, os.R_OK):
            raise UserNotFound(
                    '%s.totp does not exist or is not readable' % user)

        # Load the secrets file -- we always need it
        fh = open(totp_file, 'r')
        # secret is always the first entry
        secret = fh.readline()
        secret = secret.strip()

        # This should immediately tell us if there are problems with the
        # secret as read from the file.
        try:
            self.totp = pyotp.TOTP(secret)

            self.now_token     = self.totp.now()
            self.now_timestamp = int(time.time())

        except Exception, ex:
            raise UserFileError('Failed to generate totp: %s' % ex.message)

        logger.debug('Found a sane secret in the file, using it')

        while True:
            line = fh.readline()

            if line == '':
                break

            line = line.strip()

            if line[0] == '"':
                if line[2:12] == 'RATE_LIMIT':
                    (tries, interval) = line[13:].split(' ')
                    self.rate_limit = (int(tries), int(interval))
                    logger.debug('rate_limit=%s' % str(self.rate_limit))

                elif line[2:13] == 'WINDOW_SIZE':
                    self.window_size = int(line[14:])
                    if self.window_size > 0 and self.window_size < 3:
                        self.window_size = 3
                    logger.debug('window_size=%s' % self.window_size)

                # Ignore DISALLOW_REUSE for now -- we always disallow reuse

            # Scratch code tokens are 8-digit
            elif len(line) == 8:
                try:
                    self.scratch_tokens.append(int(line))
                    logger.debug('Found a scratch-code token, adding it')
                except ValueError:
                    logger.debug('Non-numeric scratch token found')
                    # don't fail, just pretend we didn't see it
                    continue

        fh.close()

    def verify_token(self, token):
        # load the status file and keep it locked while we do verification
        # Load used timestamps
        status_file = os.path.join(self.status_dir, self.user) + '.json'
        logger.debug('Loading user status from: %s' % status_file)

        new_status = {
                'fail_timestamps':     [],
                'success_timestamps':  [],
                'used_scratch_tokens': []
                }

        # Don't let anyone but ourselves see the contents of the status file
        os.umask(0077)

        # we exclusive-lock the file to prevent race conditions resulting
        # in potential token reuse.
        if os.access(status_file, os.R_OK):
            logger.debug('%s exists, opening r+' % status_file)
            fh = open(status_file, 'r+')
            flock(fh, LOCK_EX)
            try:
                status = json.load(fh)
            except:
                # We fail out of caution, though if someone wanted to 
                # screw things up, they could have done so without making
                # the file un-parseable by json -- all they need to do is to
                # erase the file.
                raise UserFileError(
                        'Error parsing the status file for: %s' % self.user)

            #fh.truncate(0)
            fh.seek(0)
        else:
            logger.debug('%s does not exist, opening w' % status_file)
            fh = open(status_file, 'w')
            flock(fh, LOCK_EX)
            status = new_status

        used_tokens = []

        for timestamp in status['success_timestamps']:
            # trim any timestamps that are older than (30s + WINDOW_SIZE)
            if timestamp < self.now_timestamp-(30+(self.window_size*10)):
                continue

            at_token = self.totp.at(timestamp)

            if at_token not in used_tokens:
                used_tokens.append(at_token)

            new_status['success_timestamps'].append(timestamp)

        new_status['used_scratch_tokens'] = status['used_scratch_tokens']

        logger.debug('used_tokens=%s' % used_tokens)

        # are you being rate-limited right now?
        for timestamp in status['fail_timestamps']:
            # trim any timestamps that are too old to consider
            if timestamp < self.now_timestamp-(30+self.rate_limit[1]):
                continue

            new_status['fail_timestamps'].append(timestamp)
            
        if len(new_status['fail_timestamps']) >= self.rate_limit[0]:
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
                    if token in status['used_scratch_tokens']:
                        success = (False, 'Scratch-token already used once')
                    elif token not in self.scratch_tokens:
                        success = (False, 'Not a valid scratch-token')
                    else:
                        success = (True, 'Scratch-token used')
                        new_status['used_scratch_tokens'].append(token)

                elif token >= 0:
                    logger.debug('A regular token is used')

                    # has it been used before?
                    if token in used_tokens:
                        success = (False, 'Token has already been used once')
                    elif token == self.now_token:
                        success = (True, 'Valid token used')
                    else:
                        # not a valid token right now
                        success = (False, 'Not a valid token')
                        if self.window_size > 0:
                            # okay, let's try within the window_size
                            start = self.now_timestamp-(self.window_size*10)
                            end   = self.now_timestamp+(self.window_size*10)
                            for timestamp in xrange(start, end, 10):
                                at_token = self.totp.at(timestamp)
                                if at_token == token:
                                    self.used_timestamp = timestamp
                                    self.used_token = token
                                    success = (True, 
                                        'Valid token within window size used')
                                    break

            # Adjust status accordingly
            if self.used_timestamp:
                record_timestamp = self.used_timestamp
            else:
                record_timestamp = self.now_timestamp

            if success[0] == True:
                new_status['success_timestamps'].append(record_timestamp)
            else:
                new_status['fail_timestamps'].append(record_timestamp)

        json.dump(new_status, fh, indent=4)
        fh.truncate()

        flock(fh, LOCK_UN)
        fh.close()

        logger.debug('success=%s' % str(success))

        if success[0] == False:
            raise VerifyFailed(success[1])

        return success[1]

class GoogleAuthenticator:

    def __init__(self, secrets_dir, status_dir):
        self.secrets_dir = secrets_dir
        self.status_dir  = status_dir

    def verify_user_token(self, user, token):
        user = GAUser(user, self.secrets_dir, self.status_dir)
        return user.verify_token(token)


