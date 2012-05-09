#!/usr/bin/python -tt

import os
import sys
import base64
import hashlib
import hmac
import getpass

from Crypto.Cipher import AES
from passlib.utils.pbkdf2 import pbkdf2

from optparse import OptionParser

AES_BLOCK_SIZE = 16
KDF_ITER       = 2000
SALT_SIZE      = 32
KEY_SIZE       = 32

def encrypt_secret(data, pincode):
    # generate 2 random salts to generate the aes key and hmac key
    salt = os.urandom(SALT_SIZE)

    # derive the key from pincode
    key = pbkdf2(pincode, salt, KDF_ITER, KEY_SIZE*2, prf='hmac-sha256')

    aes_key  = key[:KEY_SIZE]
    hmac_key = key[KEY_SIZE:]

    pad = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
    data = data + pad * chr(pad)
    iv_bytes = os.urandom(AES_BLOCK_SIZE)
    cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    data = iv_bytes + cypher.encrypt(data)
    sig = hmac.new(hmac_key, data, hashlib.sha256).digest()

    # jab it all together in a base64-encrypted format
    outstr = ('aes256+hmac256$' 
             + base64.b64encode(salt).replace('\n', '') + '$'
             + base64.b64encode(data+sig).replace('\n', ''))

    return outstr

def encrypt_totp_file(path, pincode, output):
    fh = open(path, 'r')
    contents = fh.read()
    fh.close()

    lines = contents.split('\n')

    # secret is always the first line
    secret = lines[0]

    # Check to make sure it's not already encrypted
    if secret.find('aes256+hmac256') == 0:
        print >> sys.stderr, '%s is already encrypted' % path
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

