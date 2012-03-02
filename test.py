#!/usr/bin/python -tt
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
import unittest

import pyotp
import time
import logging

import totpcgi
import totpcgi.backends

import os
import subprocess

secrets_dir = 'test/secrets'
state_dir   = 'test/state'

pg_connect_string = ''

STATE_BACKEND  = 'File'
SECRET_BACKEND = 'File'

logger = logging.getLogger('totpcgi')
logger.setLevel(logging.DEBUG)

ch = logging.FileHandler('test.log')
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(levelname)s:%(funcName)s:"
                              "%(lineno)s] %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

def getStateBackend():
    if STATE_BACKEND == 'File':
        state_be = totpcgi.backends.GAStateBackendFile(state_dir)

    elif STATE_BACKEND == 'Postgresql':
        state_be = totpcgi.backends.GAStateBackendPostgresql(pg_connect_string)

    return state_be

def getSecretBackend():
    if SECRET_BACKEND == 'File':
        secret_be = totpcgi.backends.GASecretBackendFile(secrets_dir)

    return secret_be

def cleanState(user='valid'):
    logger.debug('Cleaning state for user %s' % user)
    state_be = getStateBackend()
    state_be._remove_user_state(user)

def setCustomState(state, user='valid'):
    logger.debug('Setting custom state for user %s' % user)
    state_be = getStateBackend()
    state_be.get_user_state(user)
    state_be.update_user_state(user, state)

def getValidUser():
    state_be = getStateBackend()
    secret_be = getSecretBackend()
    return totpcgi.GAUser('valid', secret_be, state_be)

class GATest(unittest.TestCase):
    def setUp(self):
        # Remove any existing state files for user "valid"
        cleanState()

    def tearDown(self):
        cleanState()

    def testValidSecretParsing(self):
        logger.debug('Running testValidSecretParsing')

        gau = getValidUser()

        self.assertEqual(gau.secret.totp.secret, 'VN7J5UVLZEP7ZAGM',
                'Secret read from valid.totp did not match')
        self.assertEqual(gau.user, 'valid', 
                'User did not match')
        self.assertEqual(gau.secret.rate_limit, (4, 40),
                'RATE_LIMIT did not parse correctly')
        self.assertEqual(gau.secret.window_size, 18,
                'WINDOW_SIZE did not parse correctly')

        scratch_tokens = [88709766,11488461,27893432,60474774,10449492]

        self.assertItemsEqual(scratch_tokens, gau.secret.scratch_tokens)

    def testInvalidSecretParsing(self):
        logger.debug('Running testInvalidSecretParsing')

        state_be = getStateBackend()
        secret_be = getSecretBackend()

        with self.assertRaises(totpcgi.UserSecretError):
            totpcgi.GAUser('invalid', secret_be, state_be)

    def testInvalidUsername(self):
        logger.debug('Running testInvalidUsername')
        
        state_be = getStateBackend()
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 
                'invalid characters'):
            gau = totpcgi.GAUser('../../etc/passwd', secrets_dir, state_be)

    def testNonExistentValidUser(self):
        logger.debug('Running testNonExistentValidUser')
        
        state_be = getStateBackend()
        secret_be = getSecretBackend()
        with self.assertRaises(totpcgi.UserNotFound):
            gau = totpcgi.GAUser('bob@example.com', secret_be, state_be)
    
    def testValidToken(self):
        logger.debug('Running testValidToken')

        gau = getValidUser()
        totp = pyotp.TOTP(gau.secret.totp.secret)
        token = totp.now()
        self.assertEqual(gau.verify_token(token), 'Valid token used')

        # try using it again
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(token)

        # and again, to make sure it is preserved in state
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(token)

    def testWindowSize(self):
        logger.debug('Running testWindowSize')
        gau = getValidUser()
        totp = pyotp.TOTP(gau.secret.totp.secret)
        # get a token from 60 seconds ago
        past_token = totp.at(int(time.time())-60)
        future_token = totp.at(int(time.time())+60)
        logger.debug('past_token=%s' % past_token)
        logger.debug('future_token=%s' % future_token)

        # this should fail
        gau.secret.window_size = 0
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(past_token)
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(future_token)

        # this should work
        gau.secret.window_size = 10
        self.assertEqual(gau.verify_token(past_token), 
                'Valid token within window size used')
        self.assertEqual(gau.verify_token(future_token), 
                'Valid token within window size used')

        # trying to reuse them should fail
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(past_token)
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(future_token)
        
    def testRateLimit(self):
        logger.debug('Running testRateLimit')
        
        gau = getValidUser()

        # just in case the lightning strikes at that very number
        if gau.secret.token == 555555:
            token = '555556'
        else:
            token = '555555'

        # We now fail 4 times consecutively
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(token)
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(token)
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(token)
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(token)

        # We should now get a rate-limited error
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Rate-limit'):
            gau.verify_token(token)

        # Same with a valid token
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Rate-limit'):
            gau.verify_token(gau.secret.token)

        # Make sure we recover from rate-limiting correctly
        old_timestamp = gau.secret.timestamp-(31+(gau.secret.rate_limit[1]*10))
        state = totpcgi.GAUserState()
        state.fail_timestamps = [
            old_timestamp,
            old_timestamp,
            old_timestamp,
            old_timestamp
        ]
        setCustomState(state)

        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(token)

        # Valid token should work, too
        setCustomState(state)
        self.assertEqual(gau.verify_token(gau.secret.token), 'Valid token used')
        
    def testInvalidToken(self):
        logger.debug('Running testInvalidToken')

        gau = getValidUser()
        # just in case the lightning strikes at that very number
        if gau.secret.token == 555555:
            token = '555556'
        else:
            token = '555555'

        logger.debug('Testing with an invalid 6-digit token')
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(token)

        logger.debug('Testing with a token that is too long')
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'too long'):
            cleanState()
            gau.verify_token('12345678910')

        logger.debug('Testing with a non-integer token')
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'not an integer'):
            cleanState()
            gau.verify_token('WAKKA')

        logger.debug('Testing with an invalid 8-digit scratch-token')
        with self.assertRaisesRegexp(totpcgi.VerifyFailed,
                'Not a valid scratch-token'):
            gau.verify_token('11112222')

    def testScratchTokens(self):
        gau = getValidUser()

        ret = gau.verify_token('88709766')
        self.assertEqual(ret, 'Scratch-token used')

        # try using it again
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 
                'Scratch-token already used once'):
            gau.verify_token('88709766')

        # try using another token
        ret = gau.verify_token('11488461')
        self.assertEqual(ret, 'Scratch-token used')

        # use first one again to make sure it's preserved in the state file
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 
                'Scratch-token already used once'):
            gau.verify_token('88709766')

    def testTotpCGI(self):
        # Very basic test -- it should return 'user does not exist'
        # as we cannot currently set SECRETS_DIR in the cgi on the fly
        os.environ['REMOTE_ADDR'] = '127.0.0.1'
        os.environ['QUERY_STRING'] = 'user=bupkis&token=555555&mode=PAM_SM_AUTH'

        command = ['env', 'python', 'totp.cgi']

        ret = subprocess.check_output(command)

        self.assertRegexpMatches(ret, 'bupkis.totp does not exist')

if __name__ == '__main__':
    # To test postgresql backend, do:
    # export pg_connect_string='blah blah'
    if 'pg_connect_string' in os.environ.keys():
        STATE_BACKEND = 'Postgresql'
        pg_connect_string = os.environ['pg_connect_string']

    unittest.main()

