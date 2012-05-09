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

import os
import base64
import hashlib
import hmac
import getpass
import logging
import pyotp

import totpcgi

logger = logging.getLogger('totpcgi')

from Crypto.Cipher import AES
from passlib.utils.pbkdf2 import pbkdf2
from Crypto.Random import random

AES_BLOCK_SIZE = 16
KDF_ITER       = 2000
SALT_SIZE      = 32
KEY_SIZE       = 32

def generate_secret(rate_limit=None, window_size=None, scratch_tokens=5):
    secret = pyotp.random_base32(random=random)

    gaus = totpcgi.GAUserSecret(secret)

    if rate_limit is None:
        gaus.rate_limit = (3, 30)
    if window_size is None:
        gaus.window_size = 0

    for i in xrange(scratch_tokens):
        gaus.scratch_tokens.append(str(random.randint(0, 99999999)).zfill(8))

    return gaus

def encrypt_secret(data, pincode):
    salt = os.urandom(SALT_SIZE)

    # derive a twice-long key from pincode
    key = pbkdf2(pincode, salt, KDF_ITER, KEY_SIZE*2, prf='hmac-sha256')

    # split the key in two, one used for AES, another for HMAC
    aes_key  = key[:KEY_SIZE]
    hmac_key = key[KEY_SIZE:]

    pad = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
    data = data + pad * chr(pad)
    iv_bytes = os.urandom(AES_BLOCK_SIZE)
    cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    data = iv_bytes + cypher.encrypt(data)
    sig = hmac.new(hmac_key, data, hashlib.sha256).digest()

    # jab it all together in a base64-encrypted format
    b64str = ('aes256+hmac256$' 
             + base64.b64encode(salt).replace('\n', '') + '$'
             + base64.b64encode(data+sig).replace('\n', ''))

    logger.debug('Encrypted secret: %s' % b64str)

    return b64str

def decrypt_secret(b64str, pincode):
    # split the secret into components
    try:
        (scheme, salt, ciphertext) = b64str.split('$')

        salt       = base64.b64decode(salt)
        ciphertext = base64.b64decode(ciphertext)

    except (ValueError, TypeError):
        raise totpcgi.UserSecretError('Failed to parse encrypted secret')

    key = pbkdf2(pincode, salt, KDF_ITER, KEY_SIZE*2, prf='hmac-sha256')

    aes_key  = key[:KEY_SIZE]
    hmac_key = key[KEY_SIZE:]

    sig_size = hashlib.sha256().digest_size
    sig      = ciphertext[-sig_size:]
    data     = ciphertext[:-sig_size]

    # verify hmac sig first
    if hmac.new(hmac_key, data, hashlib.sha256).digest() != sig:
        raise totpcgi.UserSecretError('Failed to verify hmac!')

    iv_bytes = data[:AES_BLOCK_SIZE]
    data     = data[AES_BLOCK_SIZE:]

    cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    data   = cypher.decrypt(data)
    secret = data[:-ord(data[-1])]

    logger.debug('Decryption successful')

    return secret
