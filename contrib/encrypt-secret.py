#!/usr/bin/python -tt

import os
import sys
import base64
import hashlib
import getpass
from Crypto.Cipher import AES
from StringIO import StringIO

from optparse import OptionParser

def encrypt_secret(secret, pincode):
    if len(pincode) > 32:
        pincode = pincode[:32]
    elif len(pincode) < 32:
        pincode = (pincode * (32/len(pincode)+1))[:32]

    aescfb = AES.new(pincode, AES.MODE_CFB)

    myhash = hashlib.sha1(secret).hexdigest()

    plaintext  = secret + myhash
    ciphertext = aescfb.encrypt(plaintext)

    return base64.b64encode(ciphertext)


def encrypt_totp_file(path, pincode, output):
    fh = open(path, 'r')
    contents = fh.read()
    fh.close()

    lines = contents.split('\n')

    # secret is always the first line
    secret = lines[0]

    # Check to make sure it's not already encrypted
    if len(secret) > 16:
        print >> sys.stderr, 'Secret is not 16 chars. Is it already encrypted?'
        sys.exit(1)

    lines[0] = encrypt_secret(secret, pincode)

    result = '\n'.join(lines)

    if output is None:
        print result

    else:
        fh = open(output, 'w')
        fh.write(result)
        fh.close()


if __name__ == '__main__':
    usage = '''usage: %prog totpfile
    This tool will prompt you for password and then encrypt the secret
    found in the totp file with the password provided.
    '''

    parser = OptionParser(usage=usage, version='0.1')
    parser.add_option('-o', '--output', dest='output', default=None,
            help='Path where to write the output.')
    parser.add_option('-i', '--in-place', dest='inplace', action='store_true',
            default=False,
            help='Modify the file in-place')

    (opts, args) = parser.parse_args()

    if len(args) == 0:
        parser.error('You must provide the path to the totp file')

    if opts.inplace:
        opts.output = args[0]

    pincode = getpass.getpass('Pincode: ')
    if pincode != getpass.getpass('Verify: '):
        print >> sys.stderr, 'Pincodes did not match'
        sys.exit(1)

    encrypt_totp_file(args[0], pincode, opts.output)

