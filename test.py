#!/usr/bin/python -tt
import unittest
import totpcgi
import pyotp
import time
import json
import sys
import os

secrets_dir = 'test/secrets'
status_dir  = 'test/status'

class GATest(unittest.TestCase):

    def cleanStatus(self, user='valid'):
        status_file = os.path.join(status_dir, '%s.json' % user)
        if os.access(status_file, os.R_OK):
            os.unlink(status_file)

    def setCustomStatus(self, status, user='valid'):
        status_file = os.path.join(status_dir, '%s.json' % user)
        fh = open(status_file, 'w')
        json.dump(status, fh, indent=4)
        fh.close()

    def setUp(self):
        # Remove any existing status files for user "valid"
        self.cleanStatus()

    def tearDown(self):
        self.cleanStatus()

    def getValidUser(self):
        return totpcgi.GAUser('valid', secrets_dir, status_dir)

    def testValidSecretParsing(self):
        gau = self.getValidUser()

        self.assertEqual(gau.totp.secret, 'VN7J5UVLZEP7ZAGM',
                'Secret read from valid.totp did not match')
        self.assertEqual(gau.user, 'valid', 
                'User did not match')
        self.assertEqual(gau.rate_limit, (4, 40),
                'RATE_LIMIT did not parse correctly')
        self.assertEqual(gau.window_size, 18,
                'WINDOW_SIZE did not parse correctly')

        scratch_tokens = [88709766,11488461,27893432,60474774,10449492]

        self.assertItemsEqual(scratch_tokens, gau.scratch_tokens)

    def testInvalidSecretParsing(self):
        with self.assertRaises(totpcgi.UserFileError):
            totpcgi.GAUser('invalid', secrets_dir, status_dir)

    def testInvalidUsername(self):
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 
                'invalid characters'):
            gau = totpcgi.GAUser('../../etc/passwd', secrets_dir, status_dir)

    def testNonExistentValidUser(self):
        with self.assertRaises(totpcgi.UserNotFound):
            gau = totpcgi.GAUser('bob@example.com', secrets_dir, status_dir)
    
    def testValidToken(self):
        gau = self.getValidUser()
        totp = pyotp.TOTP(gau.totp.secret)
        token = totp.now()
        self.assertEqual(gau.verify_token(token), 'Valid token used')

        # try using it again
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(token)

        # and again, to make sure it is preserved in status
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'been used once'):
            gau.verify_token(token)

    def testWindowSize(self):
        gau = self.getValidUser()
        totp = pyotp.TOTP(gau.totp.secret)
        # get a token from 60 seconds ago
        past_token = totp.at(int(time.time())-60)
        future_token = totp.at(int(time.time())+60)

        # this should fail
        gau.window_size = 0
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(past_token)
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(future_token)

        # this should work
        gau.window_size = 10
        self.assertEqual(gau.verify_token(past_token), 
                'Valid token within window size used')
        self.assertEqual(gau.verify_token(future_token), 
                'Valid token within window size used')

    def testRateLimit(self):
        gau = self.getValidUser()

        # just in case the lightning strikes at that very number
        if gau.now_token == 555555:
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
            gau.verify_token(gau.now_token)

        # Make sure we recover from rate-limiting correctly
        old_timestamp = gau.now_timestamp-(31+(gau.rate_limit[1]*10))
        status = {
                'fail_timestamps': [
                    old_timestamp,
                    old_timestamp,
                    old_timestamp,
                    old_timestamp
                    ],
                'success_timestamps': [],
                'used_scratch_tokens': []
                }
        self.setCustomStatus(status)

        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(token)

        # Valid token should work, too
        self.setCustomStatus(status)
        self.assertEqual(gau.verify_token(gau.now_token), 'Valid token used')
        
    def testInvalidToken(self):
        gau = self.getValidUser()
        # just in case the lightning strikes at that very number
        if gau.now_token == 555555:
            token = '555556'
        else:
            token = '555555'

        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'Not a valid token'):
            gau.verify_token(token)

        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'too long'):
            self.cleanStatus()
            gau.verify_token('12345678910')

        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 'not an integer'):
            self.cleanStatus()
            gau.verify_token('WAKKA')

        with self.assertRaisesRegexp(totpcgi.VerifyFailed,
                'Not a valid scratch-token'):
            gau.verify_token('11112222')

    def testScratchTokens(self):
        gau = self.getValidUser()

        ret = gau.verify_token('88709766')
        self.assertEqual(ret, 'Scratch-token used')

        # try using it again
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 
                'Scratch-token already used once'):
            gau.verify_token('88709766')

        # try using another token
        ret = gau.verify_token('11488461')
        self.assertEqual(ret, 'Scratch-token used')

        # use first one again to make sure it's preserved in the status file
        with self.assertRaisesRegexp(totpcgi.VerifyFailed, 
                'Scratch-token already used once'):
            gau.verify_token('88709766')


if __name__ == '__main__':
    unittest.main()
