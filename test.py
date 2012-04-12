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

secrets_dir  = 'test/secrets'
pincode_file = 'test/secrets/pincodes'
state_dir    = 'test/state'

pg_connect_string = ''

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

    if PINCODE_BACKEND == 'File':
        backends.pincode_backend = totpcgi.backends.file.GAPincodeBackend(pincode_file)


    return backends

def getCurrentToken(secret):
    totp = pyotp.TOTP(secret)
    token = str(totp.now()).zfill(6)
    return token

def setCustomPincode(pincode, algo='6', user='valid', makedb=True, addjunk=True):
    if os.access(pincode_file, os.W_OK):
        os.unlink(pincode_file)

    if algo == '2a':
        hashcode = bcrypt.hashpw(pincode, bcrypt.gensalt())
    elif algo == 'junk':
        hashcode = '$junk$passthepepper$thisisclearlyjunk'
    else:
        salt_str = '$' + algo + '$' + 'notthebestsalteh'
        hashcode = crypt.crypt(pincode, salt_str)

    logger.debug('generated hashcode=%s' % hashcode)

    fh = open(pincode_file, 'w')
    line = '%s:%s' % (user, hashcode)

    if addjunk:
        line += ':junk'

    logger.debug('Pincode line is: %s' % line)

    fh.write('%s\n' % line)
    fh.close()

    if makedb:
        import anydbm
        pincode_db_file = pincode_file + '.db'
        if os.access(pincode_db_file, os.W_OK):
            os.unlink(pincode_db_file)

        db = anydbm.open(pincode_db_file, 'c')
        db[user] = hashcode
        db.close()
    
def cleanState(user='valid'):
    logger.debug('Cleaning state for user %s' % user)
    backends = getBackends()
    backends.state_backend._remove_user_state(user)

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

        backends = getBackends()

        with self.assertRaises(totpcgi.UserSecretError):
            totpcgi.GAUser('invalid', backends)

    def testInvalidUsername(self):
        logger.debug('Running testInvalidUsername')
        
        backends = getBackends()

        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 
                'invalid characters'):
            gau = totpcgi.GAUser('../../etc/passwd', backends)

    def testNonExistentValidUser(self):
        logger.debug('Running testNonExistentValidUser')

        backends = getBackends()
        
        with self.assertRaises(totpcgi.UserNotFound):
            gau = totpcgi.GAUser('bob@example.com', backends)
    
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

        command = ['env', 'python', 'totp.cgi', 'totpcgi.conf']

        ret = subprocess.check_output(command)

        self.assertRegexpMatches(ret, 'bupkis.totp does not exist')

    def testPincodes(self):
        logger.debug('Running testPincodes')

        logger.debug('Testing in non-required mode')

        backends = getBackends()

        ga = totpcgi.GoogleAuthenticator(backends)
        gau = getValidUser()

        pincode   = 'wakkawakka'
        tokencode = str(gau.secret.token).zfill(6)

        token = pincode + tokencode

        logger.debug('Testing without pincodes file')
        with self.assertRaisesRegexp(totpcgi.UserNotFound, 
                'pincodes file not found'):
            ga.verify_user_token('valid', token)

        logger.debug('Testing with pincodes.db older than pincodes')
        setCustomPincode(pincode, '6', user='valid', makedb=True)
        setCustomPincode('blarg', '6', user='valid', makedb=False)

        with self.assertRaisesRegexp(totpcgi.UserPincodeError,
            'Pincode did not match'):
            ga.verify_user_token('valid', token)

        logger.debug('Testing with fallback to pincodes')
        setCustomPincode('blarg', '6', user='donotwant', makedb=True)
        setCustomPincode(pincode, '6', user='valid', makedb=False)
        pincode_db_file = pincode_file + '.db'
        # Touch it, so it's newer than pincodes 
        os.utime(pincode_db_file, None)

        ret = ga.verify_user_token('valid', token)
        self.assertEqual(ret, 'Valid token used')

        cleanState()

        logger.debug('Testing without junk at the end')
        setCustomPincode(pincode, '6', user='valid', makedb=False, addjunk=False)
        ret = ga.verify_user_token('valid', token)
        self.assertEqual(ret, 'Valid token used')

        cleanState()

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
        setCustomPincode(pincode, algo='2a')
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

        logger.debug('Testing with pincode+scratch-code')
        ret = ga.verify_user_token('valid', pincode+'11488461')
        self.assertEqual(ret, 'Scratch-token used')

        logger.debug('Testing with pincode+invalid-scratch-code')
        # Because it's an invalid 8-digit scratch code, it will
        # treat it as a 6-digit tokencode
        with self.assertRaisesRegexp(totpcgi.UserPincodeError,
            'Pincode did not match'):
            ret = ga.verify_user_token('valid', pincode+'00000000')

        cleanState()

        logger.debug('Turning on pincode enforcing')
        ga = totpcgi.GoogleAuthenticator(backends, require_pincode=True)

        logger.debug('Trying valid token without pincode')
        with self.assertRaisesRegexp(totpcgi.UserPincodeError,
            'Pincode is required'):
            ga.verify_user_token('valid', tokencode)

        cleanState()

        logger.debug('Trying valid scratch token without pincode')
        with self.assertRaisesRegexp(totpcgi.UserPincodeError,
            'Pincode is required'):
            ga.verify_user_token('valid', '11488461')

        cleanState()

        logger.debug('Trying valid token with pincode in enforcing')
        ret = ga.verify_user_token('valid', token)
        self.assertEqual(ret, 'Valid token used')
        
        cleanState()

        logger.debug('Testing valid pincode+scratch-code in enforcing')
        ret = ga.verify_user_token('valid', pincode+'11488461')
        self.assertEqual(ret, 'Scratch-token used')

        cleanState()

        logger.debug('Testing with valid token but invalid pincode')
        with self.assertRaisesRegexp(totpcgi.UserPincodeError,
            'Pincode did not match'):
            ga.verify_user_token('valid', 'blarg'+tokencode)

        cleanState()

        logger.debug('Testing with valid pincode but invalid token')
        with self.assertRaisesRegexp(totpcgi.VerifyFailed,
            'Not a valid token'):
            ga.verify_user_token('valid', pincode+'555555')
        


if __name__ == '__main__':
    assert sys.version_info[0] >= 2 and sys.version_info[1] >= 7, \
        'Test suite requires python >= 2.7'

    # To test postgresql backend, do:
    # export pg_connect_string='blah blah'
    if 'pg_connect_string' in os.environ.keys():
        STATE_BACKEND = 'pgsql'
        pg_connect_string = os.environ['pg_connect_string']

    unittest.main()

