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

import sys
import os
import subprocess

import bcrypt
import crypt

import anydbm

secrets_dir  = 'test/'
pincode_file = 'test/pincodes'
state_dir    = 'test/state'

pg_connect_string = ''
ldap_dn = ''
ldap_url = ''
ldap_cacert = ''

SECRET_BACKEND  = 'File'
PINCODE_BACKEND = 'File'
STATE_BACKEND   = 'File'

logger = logging.getLogger('totpcgi')
logger.setLevel(logging.DEBUG)

ch = logging.FileHandler('test.log')
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(levelname)s:%(funcName)s:"
                              "%(lineno)s] %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

VALID_SECRET = None
VALID_SCRATCH_TOKENS = []

def db_connect():
    import psycopg2
    conn = psycopg2.connect(pg_connect_string)
    return conn

def getBackends():
    import totpcgi
    import totpcgi.backends
    backends = totpcgi.backends.Backends()

    import totpcgi.backends.file
    if STATE_BACKEND == 'File':
        backends.state_backend = totpcgi.backends.file.GAStateBackend(state_dir)

    elif STATE_BACKEND == 'pgsql':
        import totpcgi.backends.pgsql
        backends.state_backend = totpcgi.backends.pgsql.GAStateBackend(pg_connect_string)

    if SECRET_BACKEND == 'File':
        backends.secret_backend = totpcgi.backends.file.GASecretBackend(secrets_dir)
    elif SECRET_BACKEND == 'pgsql':
        backends.secret_backend = totpcgi.backends.pgsql.GASecretBackend(pg_connect_string)

    if PINCODE_BACKEND == 'File':
        backends.pincode_backend = totpcgi.backends.file.GAPincodeBackend(pincode_file)
    elif PINCODE_BACKEND == 'pgsql':
        backends.pincode_backend = totpcgi.backends.pgsql.GAPincodeBackend(pg_connect_string)
    elif PINCODE_BACKEND == 'ldap':
        import totpcgi.backends.ldap
        backends.pincode_backend = totpcgi.backends.ldap.GAPincodeBackend(ldap_url, ldap_dn, ldap_cacert)

    return backends

def getCurrentToken(secret):
    totp = pyotp.TOTP(secret)
    token = str(totp.now()).zfill(6)
    return token

def setCustomPincode(pincode, algo='sha256', user='valid', makedb=True, addjunk=False):
    hashcode = totpcgi.utils.hash_pincode(pincode, algo=algo)
    logger.debug('generated hashcode=%s' % hashcode)

    if not makedb and addjunk:
        hashcode += ':junk'

    backends = getBackends()

    if PINCODE_BACKEND == 'File':
        backends.pincode_backend.save_user_hashcode(user, hashcode, makedb=makedb)

    elif PINCODE_BACKEND == 'pgsql':
        backends.pincode_backend.save_user_hashcode(user, hashcode)

    
def cleanState(user='valid'):
    logger.debug('Cleaning state for user %s' % user)
    backends = getBackends()
    backends.state_backend.delete_user_state(user)

def setCustomState(state, user='valid'):
    logger.debug('Setting custom state for user %s' % user)
    backends = getBackends()
    backends.state_backend.get_user_state(user)
    backends.state_backend.update_user_state(user, state)

def getValidUser():
    backends = getBackends()
    return totpcgi.GAUser('valid', backends)

class GATest(unittest.TestCase):
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

        self.assertEqual(secret.totp.secret, VALID_SECRET,
                'Secret read from valid.totp did not match')
        self.assertEqual(gau.user, 'valid', 
                'User did not match')
        self.assertEqual(secret.rate_limit, (4, 30),
                'RATE_LIMIT did not parse correctly')
        self.assertEqual(secret.window_size, 17,
                'WINDOW_SIZE did not parse correctly')

        compare_tokens = []
        for token in VALID_SCRATCH_TOKENS:
            compare_tokens.append(int(token))

        self.assertItemsEqual(compare_tokens, secret.scratch_tokens)

    def testInvalidSecretParsing(self):
        logger.debug('Running testInvalidSecretParsing')

        backends = getBackends()

        gau = totpcgi.GAUser('invalid', backends)
        with self.assertRaises(totpcgi.UserSecretError):
            gau.verify_token(555555)


    def testInvalidUsername(self):
        logger.debug('Running testInvalidUsername')
        
        backends = getBackends()

        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 
                'invalid characters'):
            gau = totpcgi.GAUser('../../etc/passwd', backends)

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

        totp = pyotp.TOTP(secret.totp.secret)
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
        backends = getBackends()
        secret = backends.secret_backend.get_user_secret(gau.user)
        totp = pyotp.TOTP(secret.totp.secret)

        # get some tokens from +/- 60 seconds
        past_token = totp.at(int(time.time())-60)
        future_token = totp.at(int(time.time())+60)
        logger.debug('past_token=%s' % past_token)
        logger.debug('future_token=%s' % future_token)

        # this should work
        self.assertEqual(gau.verify_token(past_token), 
                'Valid token within window size used')
        self.assertEqual(gau.verify_token(future_token), 
                'Valid token within window size used')

        # trying to reuse them should fail
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(past_token)
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(future_token)

        # get some tokens from +/- 600 seconds
        past_token = totp.at(int(time.time())-600)
        future_token = totp.at(int(time.time())+600)
        logger.debug('past_token=%s' % past_token)
        logger.debug('future_token=%s' % future_token)
        # this should fail
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(past_token)
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(future_token)

    def testRateLimit(self):
        logger.debug('Running testRateLimit')
        
        gau = getValidUser()

        backends = getBackends()
        secret = backends.secret_backend.get_user_secret(gau.user)
        token  = '555555'

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
            gau.verify_token(secret.token)

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

        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(token)

        # Valid token should work, too
        setCustomState(state)
        self.assertEqual(gau.verify_token(secret.token), 'Valid token used')
        
    def testInvalidToken(self):
        logger.debug('Running testInvalidToken')

        gau = getValidUser()
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

        ret = gau.verify_token(VALID_SCRATCH_TOKENS[0])
        self.assertEqual(ret, 'Scratch-token used')

        # try using it again
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 
                'Scratch-token already used once'):
            gau.verify_token(VALID_SCRATCH_TOKENS[0])

        # try using another token
        ret = gau.verify_token(VALID_SCRATCH_TOKENS[1])
        self.assertEqual(ret, 'Scratch-token used')

        # use first one again to make sure it's preserved in the state file
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 
                'Scratch-token already used once'):
            gau.verify_token(VALID_SCRATCH_TOKENS[0])

    def testTotpCGI(self):
        # Very basic test -- it should return 'user does not exist'
        # as we cannot currently set SECRETS_DIR in the cgi on the fly
        os.environ['REMOTE_ADDR'] = '127.0.0.1'
        os.environ['QUERY_STRING'] = 'user=bupkis&token=555555&mode=PAM_SM_AUTH'
        os.environ['PYTHONPATH'] = '.'

        command = ['env', 'python', 'cgi/totp.cgi', 'conf/totpcgi.conf']

        ret = subprocess.check_output(command)

        self.assertRegexpMatches(ret, 'bupkis.totp does not exist')

    def testPincodes(self):
        logger.debug('Running testPincodes')

        logger.debug('Testing in non-required mode')

        backends = getBackends()

        ga = totpcgi.GoogleAuthenticator(backends)
        gau = getValidUser()

        pincode   = 'wakkawakka'
        secret    = backends.secret_backend.get_user_secret(gau.user)
        tokencode = str(secret.token).zfill(6)

        token = pincode + tokencode

        if PINCODE_BACKEND == 'File':
            logger.debug('Testing without pincodes file')
            with self.assertRaisesRegexp(totpcgi.UserNotFound, 
                    'pincodes file not found'):
                ga.verify_user_token('valid', token)

            logger.debug('Testing with pincodes.db older than pincodes')
            setCustomPincode(pincode)
            setCustomPincode('blarg', makedb=False)

            with self.assertRaisesRegexp(totpcgi.UserPincodeError,
                'Pincode did not match'):
                ga.verify_user_token('valid', token)

            logger.debug('Testing with fallback to pincodes')
            pincode_db_file = pincode_file + '.db'
            os.unlink(pincode_db_file)
            os.unlink(pincode_file)
            setCustomPincode('blarg', user='donotwant')
            os.unlink(pincode_file)
            setCustomPincode(pincode, user='valid', makedb=False)
            # Touch it, so it's newer than pincodes 
            os.utime(pincode_db_file, None)

            ret = ga.verify_user_token('valid', token)
            self.assertEqual(ret, 'Valid token used')

            cleanState()

            logger.debug('Testing with junk at the end')
            setCustomPincode(pincode, makedb=False, addjunk=True)
            ret = ga.verify_user_token('valid', token)
            self.assertEqual(ret, 'Valid token used')

            cleanState()

        elif PINCODE_BACKEND == 'pgsql':
            backends.pincode_backend.delete_user_hashcode('valid')
            logger.debug('Testing without a user pincode record present')
            with self.assertRaisesRegexp(totpcgi.UserNotFound, 
                    'no pincodes record'):
                ga.verify_user_token('valid', token)


        elif PINCODE_BACKEND in ('pgsql', 'File'):
            logger.debug('Testing with 1-digit long pincode')
            setCustomPincode('1')
            ret = ga.verify_user_token('valid', '1'+tokencode)
            self.assertEqual(ret, 'Valid token used')

            cleanState()

            logger.debug('Testing with 2-digit long pincode')
            setCustomPincode('99')
            ret = ga.verify_user_token('valid', '99'+tokencode)
            self.assertEqual(ret, 'Valid token used')

            cleanState()

            logger.debug('Testing with bcrypt')
            setCustomPincode(pincode, algo='bcrypt')
            ret = ga.verify_user_token('valid', token)
            self.assertEqual(ret, 'Valid token used')

            cleanState()

            logger.debug('Testing with junk pincode')
            setCustomPincode(pincode, algo='junk')
            with self.assertRaisesRegexp(totpcgi.UserPincodeError,
                'Unsupported hashcode format'):
                ga.verify_user_token('valid', token)

            cleanState()

            setCustomPincode(pincode)

        if PINCODE_BACKEND == 'ldap':
            valid_user = os.environ['ldap_user']
            pincode    = os.environ['ldap_password']
            token      = pincode + tokencode
        else:
            valid_user = 'valid'
            pincode = 'wakkawakka'
            setCustomPincode(pincode)

        logger.debug('Testing with pincode+scratch-code')
        ret = ga.verify_user_token(valid_user, pincode+VALID_SCRATCH_TOKENS[0])
        self.assertEqual(ret, 'Scratch-token used')

        logger.debug('Testing with pincode+invalid-scratch-code')
        if PINCODE_BACKEND == 'ldap':
            raisedmsg = 'LDAP bind failed'
        else:
            raisedmsg = 'Pincode did not match'

        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            ret = ga.verify_user_token(valid_user, pincode+'00000000')

        cleanState()

        logger.debug('Turning on pincode enforcing')
        ga = totpcgi.GoogleAuthenticator(backends, require_pincode=True)

        logger.debug('Trying valid token without pincode')
        with self.assertRaisesRegexp(totpcgi.UserPincodeError,
            'Pincode is required'):
            ga.verify_user_token(valid_user, tokencode)

        cleanState()

        logger.debug('Trying valid scratch token without pincode')
        with self.assertRaisesRegexp(totpcgi.UserPincodeError,
            'Pincode is required'):
            ga.verify_user_token(valid_user, VALID_SCRATCH_TOKENS[0])

        cleanState()

        logger.debug('Trying valid token with pincode in enforcing')
        ret = ga.verify_user_token(valid_user, token)
        self.assertEqual(ret, 'Valid token used')
        
        cleanState()

        logger.debug('Testing valid pincode+scratch-code in enforcing')
        ret = ga.verify_user_token(valid_user, pincode+VALID_SCRATCH_TOKENS[0])
        self.assertEqual(ret, 'Scratch-token used')

        cleanState()

        logger.debug('Testing with valid token but invalid pincode')
        with self.assertRaisesRegexp(totpcgi.UserPincodeError, raisedmsg):
            ga.verify_user_token(valid_user, 'blarg'+tokencode)

        cleanState()

        logger.debug('Testing with valid pincode but invalid token')
        with self.assertRaisesRegexp(totpcgi.VerifyFailed,
            'Not a valid token'):
            ga.verify_user_token(valid_user, pincode+'555555')

    def testEncryptedSecret(self):
        logger.debug('Running testEncryptedSecret')

        backends = getBackends()
        ga = totpcgi.GoogleAuthenticator(backends)

        pincode = 'wakkawakka'
        setCustomPincode(pincode, user='encrypted')

        totp = pyotp.TOTP(VALID_SECRET)
        token = str(totp.now()).zfill(6)

        ga.verify_user_token('encrypted', pincode+token)

        # This should fail, as we ignore scratch tokens with encrypted secrets
        with self.assertRaisesRegexp(totpcgi.VerifyFailed,
                'Not a valid scratch-token'):
            ga.verify_user_token('encrypted', pincode+'12345678')

        cleanState(user='encrypted')

        setCustomPincode(pincode, user='encrypted-bad')
        with self.assertRaisesRegexp(totpcgi.UserSecretError,
                'Failed to'):
            ga.verify_user_token('encrypted-bad', pincode+token)

        cleanState(user='encrypted-bad')


if __name__ == '__main__':
    assert sys.version_info[0] >= 2 and sys.version_info[1] >= 7, \
        'Test suite requires python >= 2.7'

    # To test postgresql backend, do:
    # export pg_connect_string='blah blah'
    if 'pg_connect_string' in os.environ.keys():
        STATE_BACKEND = SECRET_BACKEND = PINCODE_BACKEND = 'pgsql'
        pg_connect_string = os.environ['pg_connect_string']
    
    # To test ldap backend, set env vars for
    # ldap_url, ldap_dn, ldap_cacert, ldap_user and ldap_password
    if 'ldap_url' in os.environ.keys():
        PINCODE_BACKEND = 'ldap'
        ldap_url    = os.environ['ldap_url']
        ldap_dn     = os.environ['ldap_dn']
        ldap_cacert = os.environ['ldap_cacert']

    backends = getBackends()

    # valid user
    gaus = totpcgi.utils.generate_secret(rate_limit=(4, 30))
    backends.secret_backend.save_user_secret('valid', gaus)

    VALID_SECRET = gaus.totp.secret
    VALID_SCRATCH_TOKENS = gaus.scratch_tokens

    # encrypted-secret user is same as valid, just encrypted
    backends.secret_backend.save_user_secret('encrypted', gaus, 'wakkawakka')

    # invalid user (bad secret)
    gaus = totpcgi.utils.generate_secret()
    gaus.totp.secret = 'WAKKAWAKKA'
    backends.secret_backend.save_user_secret('invalid', gaus)

    # encrypted-bad (bad encryption)
    gaus.totp.secret = 'aes256+hmac256$WAKKAWAKKA$WAKKAWAKKA'
    backends.secret_backend.save_user_secret('encrypted-bad', gaus)

    try:
        unittest.main()
    finally:
        for username in ('valid', 'invalid', 'encrypted', 'encrypted-bad'):
            backends.secret_backend.delete_user_secret(username)
