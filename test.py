#!/usr/bin/env python
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

import unittest

import pyotp
import time
import logging

import totpcgi.utils

import sys
import os
import subprocess
import totpcgi

secrets_dir = 'test/'
pincode_file = 'test/pincodes'
state_dir = 'test/state'

pg_connect_string = ''
ldap_dn = ''
ldap_url = ''
ldap_cacert = ''
mysql_connect_host = ''
mysql_connect_user = ''
mysql_connect_password = ''
mysql_connect_db = ''

SECRET_BACKEND = 'File'
PINCODE_BACKEND = 'File'
STATE_BACKEND = 'File'

logger = logging.getLogger('totpcgi')
logger.setLevel(logging.DEBUG)

ch = logging.FileHandler('test.log')
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(asctime)s] {%(module)s:%(funcName)s:%(lineno)s} %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

VALID_SECRET = None
VALID_SCRATCH_TOKENS = []


def db_connect():
    import psycopg2
    conn = psycopg2.connect(pg_connect_string)
    return conn


def getBackends():
    import totpcgi.backends
    backends = totpcgi.backends.Backends()

    import totpcgi.backends.file
    if STATE_BACKEND == 'File':
        backends.state_backend = totpcgi.backends.file.GAStateBackend(state_dir)
    elif STATE_BACKEND == 'pgsql':
        import totpcgi.backends.pgsql
        backends.state_backend = totpcgi.backends.pgsql.GAStateBackend(pg_connect_string)
    elif STATE_BACKEND == 'mysql':
        import totpcgi.backends.mysql
        backends.state_backend = totpcgi.backends.mysql.GAStateBackend(mysql_connect_host, mysql_connect_user,
                                                                       mysql_connect_password, mysql_connect_db)

    if SECRET_BACKEND == 'File':
        backends.secret_backend = totpcgi.backends.file.GASecretBackend(secrets_dir)
    elif SECRET_BACKEND == 'pgsql':
        backends.secret_backend = totpcgi.backends.pgsql.GASecretBackend(pg_connect_string)
    elif SECRET_BACKEND == 'mysql':
        backends.secret_backend = totpcgi.backends.mysql.GASecretBackend(mysql_connect_host, mysql_connect_user,
                                                                         mysql_connect_password, mysql_connect_db)

    if PINCODE_BACKEND == 'File':
        backends.pincode_backend = totpcgi.backends.file.GAPincodeBackend(pincode_file)
    elif PINCODE_BACKEND == 'pgsql':
        backends.pincode_backend = totpcgi.backends.pgsql.GAPincodeBackend(pg_connect_string)
    elif PINCODE_BACKEND == 'mysql':
        backends.pincode_backend = totpcgi.backends.mysql.GAPincodeBackend(mysql_connect_host, mysql_connect_user,
                                                                           mysql_connect_password, mysql_connect_db)
    elif PINCODE_BACKEND == 'ldap':
        import totpcgi.backends.ldap
        backends.pincode_backend = totpcgi.backends.ldap.GAPincodeBackend(ldap_url, ldap_dn, ldap_cacert)

    return backends


def setCustomPincode(pincode, algo='sha256', user='valid', addjunk=False):
    hashcode = totpcgi.utils.hash_pincode(pincode, algo=algo)
    logger.debug('generated hashcode=%s', hashcode)

    if addjunk:
        hashcode += ':junk'

    backends = getBackends()

    if PINCODE_BACKEND == 'File':
        backends.pincode_backend.save_user_hashcode(user, hashcode)

    elif PINCODE_BACKEND in ('pgsql', 'mysql'):
        backends.pincode_backend.save_user_hashcode(user, hashcode)

    
def cleanState(user='valid'):
    logger.debug('Cleaning state for user %s', user)
    backends = getBackends()
    backends.state_backend.delete_user_state(user)
    if 'ldap_user' in os.environ and user != os.environ['ldap_user']:
        cleanState(user=os.environ['ldap_user'])


def setCustomState(state, user='valid'):
    logger.debug('Setting custom state for user %s', user)
    backends = getBackends()
    backends.state_backend.get_user_state(user)
    backends.state_backend.update_user_state(user, state)


def getValidUser():
    logger.debug('Setting up user valid')
    backends = getBackends()
    gau = totpcgi.GAUser('valid', backends)
    if SECRET_BACKEND == 'File':
        with open(os.path.join(secrets_dir, 'valid.totp'), 'r') as fh:
            logger.debug('valid.totp follows\n%s', fh.read())
    return gau


class GATest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)

    def assertCountEqual(*args, **kwargs):
        if sys.version_info < (3, 0):
            return unittest.TestCase.assertItemsEqual(*args, **kwargs)

        # noinspection PyCompatibility
        return unittest.TestCase.assertCountEqual(*args, **kwargs)

    def assertRaisesRegex(*args, **kwargs):
        if sys.version_info < (3, 0):
            return unittest.TestCase.assertRaisesRegexp(*args, **kwargs)

        # noinspection PyCompatibility
        return unittest.TestCase.assertRaisesRegex(*args, **kwargs)

    def setUp(self):
        # Remove any existing state files for user "valid"
        cleanState()

    def tearDown(self):
        cleanState()
        if os.access(pincode_file, os.W_OK):
            os.unlink(pincode_file)
        if os.access(pincode_file + '.db', os.W_OK):
            os.unlink(pincode_file + '.db')

    def testValidSecretParsing(self):
        logger.debug('Running testValidSecretParsing')

        gau = getValidUser()

        backends = getBackends()
        secret = backends.secret_backend.get_user_secret(gau.user)

        self.assertEqual(secret.otp.secret, VALID_SECRET,
                         'Secret read from valid.totp did not match')
        self.assertEqual(gau.user, 'valid', 
                         'User did not match')
        self.assertEqual(secret.rate_limit, (4, 30),
                         'RATE_LIMIT did not parse correctly')
        self.assertEqual(secret.window_size, 3,
                         'WINDOW_SIZE did not parse correctly')

        compare_tokens = []
        for token in VALID_SCRATCH_TOKENS:
            compare_tokens.append(token)

        self.assertCountEqual(compare_tokens, secret.scratch_tokens)

    def testInvalidSecretParsing(self):
        logger.debug('Running testInvalidSecretParsing')

        backends = getBackends()

        gau = totpcgi.GAUser('invalid', backends)
        with self.assertRaises(totpcgi.UserSecretError):
            gau.verify_token(555555)

    def testInvalidUsername(self):
        logger.debug('Running testInvalidUsername')
        
        backends = getBackends()

        with self.assertRaisesRegex(totpcgi.VerifyFailed,
                                    'invalid characters'):
            totpcgi.GAUser('../../etc/passwd', backends)

    def testNonExistentValidUser(self):
        logger.debug('Running testNonExistentValidUser')

        backends = getBackends()
        
        gau = totpcgi.GAUser('bob@example.com', backends)
        with self.assertRaises(totpcgi.UserNotFound):
            gau.verify_token(555555)
    
    def testValidToken(self):
        logger.debug('Running testValidToken')

        gau = getValidUser()
        backends = getBackends()
        secret = backends.secret_backend.get_user_secret(gau.user)

        totp = pyotp.TOTP(secret.otp.secret)
        token = totp.now()
        self.assertEqual(gau.verify_token(token), 'Valid TOTP token used')

        # try using it again
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(token)

        # and again, to make sure it is preserved in state
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(token)

        gau = totpcgi.GAUser('hotp', backends)
        # Save custom state for HOTP user, as some backends rely on it to trigger HOTP mode
        state = totpcgi.GAUserState()
        state.counter = 0
        setCustomState(state, 'hotp')

        hotp = pyotp.HOTP(secret.otp.secret)
        token = hotp.at(0)
        self.assertEqual(gau.verify_token(token), 'Valid HOTP token used')

        # make sure the counter now validates at 1 and 2
        self.assertEqual(gau.verify_token(hotp.at(1)), 'Valid HOTP token used')
        self.assertEqual(gau.verify_token(hotp.at(2)), 'Valid HOTP token used')

        # make sure trying "1" or "2" fails now
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'HOTP token failed to verify'):
            gau.verify_token(hotp.at(1))
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'HOTP token failed to verify'):
            gau.verify_token(hotp.at(2))

        # but we're good to go at 3
        self.assertEqual(gau.verify_token(hotp.at(3)), 'Valid HOTP token used')

        # and we're good to go with 7, which is max window size
        self.assertEqual(gau.verify_token(hotp.at(7)), 'Valid HOTP token within window size used')

        # Trying with "5" should fail now
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'HOTP token failed to verify'):
            gau.verify_token(hotp.at(5))

        # but we're good to go at 8
        self.assertEqual(gau.verify_token(hotp.at(8)), 'Valid HOTP token used')

        # should fail with 13, which is beyond window size of 9+3
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'HOTP token failed to verify'):
            gau.verify_token(hotp.at(13))

        cleanState('hotp')

    def testTOTPWindowSize(self):
        logger.debug('Running testWindowSize')
        gau = getValidUser()
        backends = getBackends()
        secret = backends.secret_backend.get_user_secret(gau.user)
        totp = pyotp.TOTP(secret.otp.secret)

        # go back until we get the previous token
        timestamp = int(time.time())
        token = totp.at(timestamp)

        past_token = future_token = None
        past_timestamp = future_timestamp = timestamp

        while past_token is None or past_token == token:
            past_timestamp -= 10
            past_token = totp.at(past_timestamp)

        while future_token is None or future_token == token:
            future_timestamp += 10
            future_token = totp.at(future_timestamp)

        logger.debug('past_token=%s', past_token)
        logger.debug('token=%s', token)
        logger.debug('future_token=%s', future_token)

        # this should work
        self.assertEqual(gau.verify_token(past_token), 
                         'Valid TOTP token within window size used')
        self.assertEqual(gau.verify_token(future_token), 
                         'Valid TOTP token within window size used')

        # trying to reuse them should fail
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(past_token)
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(future_token)

        # get some tokens from +/- 600 seconds
        past_token = totp.at(int(time.time())-600)
        future_token = totp.at(int(time.time())+600)
        logger.debug('past_token=%s', past_token)
        logger.debug('future_token=%s', future_token)
        # this should fail
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'TOTP token failed to verify'):
            gau.verify_token(past_token)
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'TOTP token failed to verify'):
            gau.verify_token(future_token)

    def testTOTPRateLimit(self):
        logger.debug('Running testTOTPRateLimit')
        
        gau = getValidUser()

        backends = getBackends()
        secret = backends.secret_backend.get_user_secret(gau.user)
        token = '555555'

        # We now fail 4 times consecutively
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'TOTP token failed to verify'):
            gau.verify_token(token)
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'TOTP token failed to verify'):
            gau.verify_token(token)
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'TOTP token failed to verify'):
            gau.verify_token(token)
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'TOTP token failed to verify'):
            gau.verify_token(token)

        # We should now get a rate-limited error
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'Rate-limit'):
            gau.verify_token(token)

        # Same with a valid token
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'Rate-limit'):
            gau.verify_token(secret.get_totp_token())

        # Make sure we recover from rate-limiting correctly
        old_timestamp = secret.timestamp-(31+(secret.rate_limit[1]*10))
        state = totpcgi.GAUserState()
        state.fail_timestamps = [
            old_timestamp,
            old_timestamp,
            old_timestamp,
            old_timestamp
        ]
        setCustomState(state)

        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'TOTP token failed to verify'):
            gau.verify_token(token)

        # Valid token should work, too
        setCustomState(state)
        ret = gau.verify_token(secret.get_totp_token())
        self.assertIn(ret, ('Valid TOTP token used', 'Valid TOTP token within window size used'))

    def testHOTPRateLimit(self):
        logger.debug('Running testHOTPRateLimit')

        backends = getBackends()
        # Save custom state for HOTP user, as some backends rely on it to trigger HOTP mode
        state = totpcgi.GAUserState()
        state.counter = 1
        setCustomState(state, 'hotp')

        gau = totpcgi.GAUser('hotp', backends)
        secret = backends.secret_backend.get_user_secret(gau.user)

        hotp = pyotp.HOTP(secret.otp.secret)
        token = hotp.at(1)
        self.assertEqual(gau.verify_token(token), 'Valid HOTP token used')
        # counter is now at 2

        token = '555555'

        # We now fail 4 times consecutively
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'HOTP token failed to verify'):
            gau.verify_token(token)
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'HOTP token failed to verify'):
            gau.verify_token(token)
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'HOTP token failed to verify'):
            gau.verify_token(token)
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'HOTP token failed to verify'):
            gau.verify_token(token)

        # We should now get a rate-limited error
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'Rate-limit'):
            gau.verify_token(token)

        # Same with a valid token
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'Rate-limit'):
            gau.verify_token(hotp.at(2))

        # Make sure we recover from rate-limiting correctly
        old_timestamp = secret.timestamp-(31+(secret.rate_limit[1]*10))
        state = totpcgi.GAUserState()
        state.fail_timestamps = [
            old_timestamp,
            old_timestamp,
            old_timestamp,
            old_timestamp
        ]
        state.counter = 2
        setCustomState(state, 'hotp')

        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'HOTP token failed to verify'):
            gau.verify_token(token)

        # Valid token should work, too
        setCustomState(state, 'hotp')
        self.assertEqual(gau.verify_token(hotp.at(2)), 'Valid HOTP token used')
        cleanState('hotp')
        
    def testInvalidToken(self):
        logger.debug('Running testInvalidToken')

        gau = getValidUser()
        token = '555555'

        logger.debug('Testing with an invalid 6-digit token')
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'TOTP token failed to verify'):
            gau.verify_token(token)

        logger.debug('Test right away with a valid token')
        backends = getBackends()
        secret = backends.secret_backend.get_user_secret(gau.user)

        totp = pyotp.TOTP(secret.otp.secret)
        validtoken = totp.now()
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(validtoken)

        logger.debug('Testing with a non-integer token')
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'not an integer'):
            cleanState()
            gau.verify_token('WAKKA')

        logger.debug('Testing with an invalid 8-digit scratch-token')
        with self.assertRaisesRegex(totpcgi.VerifyFailed,
                                    'Not a valid scratch-token'):
            gau.verify_token('11112222')

    def testScratchTokens(self):
        gau = getValidUser()

        ret = gau.verify_token(VALID_SCRATCH_TOKENS[0])
        self.assertEqual(ret, 'Scratch-token used')

        # try using it again
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 
                                    'Scratch-token already used once'):
            gau.verify_token(VALID_SCRATCH_TOKENS[0])

        # try using another token
        ret = gau.verify_token(VALID_SCRATCH_TOKENS[1])
        self.assertEqual(ret, 'Scratch-token used')

        # use first one again to make sure it's preserved in the state file
        with self.assertRaisesRegex(totpcgi.VerifyFailed, 
                                    'Scratch-token already used once'):
            gau.verify_token(VALID_SCRATCH_TOKENS[0])

    def testTotpCGI(self):
        # Very basic test -- it should return 'user not found'
        os.environ['REMOTE_ADDR'] = '127.0.0.1'
        os.environ['QUERY_STRING'] = 'user=bupkis&token=555555&mode=PAM_SM_AUTH'
        os.environ['PYTHONPATH'] = '.'

        command = ['env', 'python', 'cgi/totp.cgi', 'conf/totpcgi.conf']

        ret = subprocess.check_output(command).decode('utf-8')

        self.assertTrue(ret.find('bupkis.totp does not exist') >= 0)

    def testPincodes(self):
        logger.debug('Running testPincodes')

        logger.debug('Testing in non-required mode')

        backends = getBackends()

        ga = totpcgi.GoogleAuthenticator(backends)
        gau = getValidUser()

        pincode = 'wakkawakka'
        secret = backends.secret_backend.get_user_secret(gau.user)
        tokencode = secret.get_totp_token()

        token = pincode + tokencode

        logger.debug('scratch_token=%s', VALID_SCRATCH_TOKENS[0])
        logger.debug('pincode=%s', pincode)

        if PINCODE_BACKEND == 'File':
            logger.debug('Testing without pincodes file')
            with self.assertRaisesRegex(totpcgi.UserNotFound, 
                                        'pincodes file not found'):
                ga.verify_user_token('valid', token)

            cleanState()

            logger.debug('Testing with junk at the end')
            setCustomPincode(pincode, addjunk=True)
            ret = ga.verify_user_token('valid', token)
            self.assertIn(ret, ('Valid TOTP token used', 'Valid TOTP token within window size used'))

            cleanState()

        if PINCODE_BACKEND in ('pgsql', 'mysql'):
            backends.pincode_backend.delete_user_hashcode('valid')
            logger.debug('Testing without a user pincode record present')
            with self.assertRaisesRegex(totpcgi.UserNotFound, 
                                        'no pincodes record'):
                ga.verify_user_token('valid', token)

        if PINCODE_BACKEND in ('pgsql', 'mysql', 'File'):
            logger.debug('Testing with 1-digit long pincode')
            setCustomPincode('1')
            ret = ga.verify_user_token('valid', '1'+tokencode)
            self.assertIn(ret, ('Valid TOTP token used', 'Valid TOTP token within window size used'))

            cleanState()

            logger.debug('Testing with 2-digit long pincode + valid tokencode')
            setCustomPincode('99')
            ret = ga.verify_user_token('valid', '99'+tokencode)
            self.assertIn(ret, ('Valid TOTP token used', 'Valid TOTP token within window size used'))

            cleanState()

            logger.debug('Testing with 2-digit long pincode + invalid tokencode')
            setCustomPincode('99')
            with self.assertRaisesRegex(totpcgi.VerifyFailed,
                                        'TOTP token failed to verify'):
                ga.verify_user_token('valid', '99'+'000000')

            cleanState()

            logger.debug('Testing with bcrypt')
            setCustomPincode(pincode, algo='bcrypt')
            ret = ga.verify_user_token('valid', token)
            self.assertIn(ret, ('Valid TOTP token used', 'Valid TOTP token within window size used'))

            cleanState()

            logger.debug('Testing with md5')
            setCustomPincode(pincode, algo='md5')
            ret = ga.verify_user_token('valid', token)
            self.assertIn(ret, ('Valid TOTP token used', 'Valid TOTP token within window size used'))

            cleanState()

            setCustomPincode(pincode)

        if PINCODE_BACKEND == 'ldap':
            valid_user = os.environ['ldap_user']
            pincode = os.environ['ldap_password']
            token = pincode + tokencode
        else:
            valid_user = 'valid'
            pincode = 'wakkawakka'
            setCustomPincode(pincode)

        logger.debug('Testing with pincode+scratch-code')
        ret = ga.verify_user_token(valid_user, pincode+VALID_SCRATCH_TOKENS[0])
        self.assertEqual(ret, 'Scratch-token used')

        logger.debug('Testing with pincode+scratch-code (starting with 00)')
        ret = ga.verify_user_token(valid_user, pincode+VALID_SCRATCH_TOKENS[1])
        self.assertEqual(ret, 'Scratch-token used')

        logger.debug('Testing with pincode+invalid-scratch-code')

        with self.assertRaisesRegex(totpcgi.VerifyFailed, 'Not a valid scratch-token'):
            ga.verify_user_token(valid_user, pincode+'00000000')

        cleanState()

        logger.debug('Turning on pincode enforcing')
        ga = totpcgi.GoogleAuthenticator(backends, require_pincode=True)

        logger.debug('Trying valid token without pincode')
        with self.assertRaisesRegex(totpcgi.UserPincodeError,
                                    'Pincode is required'):
            ga.verify_user_token(valid_user, tokencode)

        cleanState()

        logger.debug('Trying valid scratch token without pincode')
        with self.assertRaisesRegex(totpcgi.UserPincodeError,
                                    'Pincode is required'):
            ga.verify_user_token(valid_user, VALID_SCRATCH_TOKENS[0])

        cleanState()

        logger.debug('Trying valid token with pincode in enforcing')
        ret = ga.verify_user_token(valid_user, token)
        # The tests sometimes take longer than our window
        self.assertIn(ret, ('Valid TOTP token used', 'Valid TOTP token within window size used'))
        
        cleanState()

        logger.debug('Testing valid pincode+scratch-code in enforcing')
        logger.debug('pincode=%s', pincode+VALID_SCRATCH_TOKENS[0])
        ret = ga.verify_user_token(valid_user, pincode+VALID_SCRATCH_TOKENS[0])
        self.assertEqual(ret, 'Scratch-token used')

        cleanState()

        if PINCODE_BACKEND == 'ldap':
            raisedmsg = 'LDAP bind failed'
        else:
            raisedmsg = 'Pincode did not match'

        logger.debug('Testing with valid token but invalid pincode')
        with self.assertRaisesRegex(totpcgi.UserPincodeError, raisedmsg):
            ga.verify_user_token(valid_user, 'blarg'+tokencode)

        # Refresh our token to grab the latest
        totp = pyotp.TOTP(VALID_SECRET)
        tokencode = str(totp.now()).zfill(6)
        token = pincode + tokencode
        logger.debug('Latest token=%s', token)
        logger.debug('Testing again with valid token and valid pincode')
        with self.assertRaisesRegex(totpcgi.VerifyFailed,
                                    'already been used'):
            ga.verify_user_token(valid_user, token)

        cleanState()

        logger.debug('Testing with valid pincode but invalid token')
        with self.assertRaisesRegex(totpcgi.VerifyFailed,
                                    'TOTP token failed to verify'):
            ga.verify_user_token(valid_user, pincode+'555555')

    def testEncryptedSecret(self):
        if PINCODE_BACKEND in 'ldap':
            valid_user = os.environ['ldap_user']
            pincode = os.environ['ldap_password']
        else:
            pincode = 'wakkawakka'
            valid_user = 'encrypted'
            setCustomPincode(pincode, user=valid_user)

        logger.debug('Running testEncryptedSecret')

        backends = getBackends()
        ga = totpcgi.GoogleAuthenticator(backends)

        totp = pyotp.TOTP(VALID_SECRET)
        token = str(totp.now()).zfill(6)

        ga.verify_user_token(valid_user, pincode+token)

        # This should fail, as we ignore scratch tokens with encrypted secrets
        with self.assertRaisesRegex(totpcgi.VerifyFailed,
                                    'Not a valid scratch-token'):
            ga.verify_user_token(valid_user, pincode+'12345678')

        cleanState(user=valid_user)

        # We don't need to run this for ldap
        if PINCODE_BACKEND in 'ldap':
            return

        setCustomPincode(pincode, user='encrypted-bad')
        with self.assertRaisesRegex(totpcgi.UserSecretError,
                                    'Failed to parse'):
            ga.verify_user_token('encrypted-bad', pincode+token)

        cleanState(user='encrypted-bad')


if __name__ == '__main__':
    # To test postgresql backend, do:
    # export pg_connect_string='blah blah'
    if 'pg_connect_string' in os.environ.keys():
        STATE_BACKEND = SECRET_BACKEND = PINCODE_BACKEND = 'pgsql'
        pg_connect_string = os.environ['pg_connect_string']
    
    # To test ldap backend, set env vars for
    # ldap_url, ldap_dn, ldap_cacert, ldap_user and ldap_password
    if 'ldap_url' in os.environ.keys():
        PINCODE_BACKEND = 'ldap'
        ldap_url = os.environ['ldap_url']
        ldap_dn = os.environ['ldap_dn']
        ldap_cacert = os.environ['ldap_cacert']

    if 'mysql_connect_host' in os.environ.keys():
        STATE_BACKEND = SECRET_BACKEND = PINCODE_BACKEND = 'mysql'
        mysql_connect_host = os.environ['mysql_connect_host']
        mysql_connect_user = os.environ['mysql_connect_user']
        mysql_connect_password = os.environ['mysql_connect_password']
        mysql_connect_db = os.environ['mysql_connect_db']

    be = getBackends()

    # valid user
    gaus = totpcgi.utils.generate_secret(rate_limit=(4, 30))

    # make the 2nd scratch token start with 00
    gaus.scratch_tokens[1] = '00' + gaus.scratch_tokens[1][2:]
    be.secret_backend.save_user_secret('valid', gaus)

    if 'ldap_user' in os.environ:
        be.secret_backend.save_user_secret(os.environ['ldap_user'], gaus)

    VALID_SECRET = gaus.otp.secret
    VALID_SCRATCH_TOKENS = gaus.scratch_tokens

    # hotp is using HOTP mode
    gaus.set_hotp(0)
    be.secret_backend.save_user_secret('hotp', gaus)

    # switch back to totp for the rest
    gaus.counter = -1
    gaus.otp = pyotp.TOTP(VALID_SECRET)

    # encrypted-secret user is same as valid, just encrypted
    be.secret_backend.save_user_secret('encrypted', gaus, 'wakkawakka')

    # invalid user (bad secret)
    gaus = totpcgi.utils.generate_secret()
    gaus.otp.secret = 'WAKKA"WAKKA'
    be.secret_backend.save_user_secret('invalid', gaus)

    # encrypted-bad (bad encryption)
    gaus.otp.secret = 'aes256+hmac256$WAKKAWAKKA$WAKKAWAKKA'
    be.secret_backend.save_user_secret('encrypted-bad', gaus)

    try:
        unittest.main()
    finally:
        test_users = ['valid', 'invalid', 'encrypted', 'encrypted-bad', 'hotp']
        if 'ldap_user' in os.environ and os.environ['ldap_user'] not in test_users:
            test_users.append(os.environ['ldap_user'])
        for username in test_users:
            be.state_backend.delete_user_state(username)
            be.secret_backend.delete_user_secret(username)
            pass
