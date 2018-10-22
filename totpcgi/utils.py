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
import logging

import struct

import totpcgi

from Crypto.Cipher import AES
from passlib.crypto.digest import pbkdf2_hmac

logger = logging.getLogger('totpcgi')

AES_BLOCK_SIZE = 16
KDF_ITER = 2000
SALT_SIZE = 32
KEY_SIZE = 32


def hash_pincode(pincode, algo='bcrypt'):
    if algo not in ('bcrypt', 'sha256', 'sha512', 'md5'):
        raise ValueError('Unsupported algorithm: %s' % algo)

    import passlib.hash

    # if you want higher computational cost, just use bcrypt
    if algo == 'sha256':
        return passlib.hash.sha256_crypt.hash(pincode)

    if algo == 'sha512':
        return passlib.hash.sha512_crypt.hash(pincode)

    if algo == 'md5':
        # really? Okay.
        return passlib.hash.md5_crypt.hash(pincode)

    return passlib.hash.bcrypt.hash(pincode)


def generate_secret(rate_limit=(3, 30), window_size=3, scratch_tokens=5, bs=80):
    # os.urandom expects bytes, so we divide by 8
    secret = base64.b32encode(os.urandom(int(bs/8))).decode('utf-8')

    gaus = totpcgi.GAUserSecret(secret)

    gaus.rate_limit = rate_limit
    gaus.window_size = window_size

    for i in range(scratch_tokens):
        token = str(struct.unpack('I', os.urandom(4))[0]).zfill(8)[-8:]
        gaus.scratch_tokens.append(token)

    return gaus


def encrypt_secret(strdata, pincode):
    data = strdata.encode('utf-8')
    salt = os.urandom(SALT_SIZE)

    # derive a twice-long key from pincode
    key = pbkdf2_hmac('sha256', pincode, salt, KDF_ITER, KEY_SIZE*2)

    # split the key in two, one used for AES, another for HMAC
    aes_key = key[:KEY_SIZE]
    hmac_key = key[KEY_SIZE:]

    pad = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
    data += pad * bytearray((pad,))
    iv_bytes = os.urandom(AES_BLOCK_SIZE)
    cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    data = iv_bytes + cypher.encrypt(data)
    sig = hmac.new(hmac_key, data, hashlib.sha256).digest()

    # jab it all together in a base64-encrypted format
    b64str = ('aes256+hmac256$' 
              + base64.b64encode(salt).decode('utf-8').replace('\n', '') + '$'
              + base64.b64encode(data+sig).decode('utf-8').replace('\n', ''))

    logger.debug('Encrypted secret: %s', b64str)

    return b64str


def decrypt_secret(b64str, pincode):
    # split the secret into components
    try:
        (scheme, salt, ciphertext) = b64str.split('$')

        salt = base64.b64decode(salt)
        ciphertext = base64.b64decode(ciphertext)

    except (ValueError, TypeError):
        raise totpcgi.UserSecretError('Failed to parse encrypted secret')

    key = pbkdf2_hmac('sha256', pincode, salt, KDF_ITER, KEY_SIZE * 2)

    aes_key = key[:KEY_SIZE]
    hmac_key = key[KEY_SIZE:]

    sig_size = hashlib.sha256().digest_size
    sig = ciphertext[-sig_size:]
    data = ciphertext[:-sig_size]

    # verify hmac sig first
    if hmac.new(hmac_key, data, hashlib.sha256).digest() != sig:
        raise totpcgi.UserSecretError('Failed to verify hmac!')

    iv_bytes = data[:AES_BLOCK_SIZE]
    data = data[AES_BLOCK_SIZE:]

    cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    data = cypher.decrypt(data)
    padlen = bytearray((data[-1],))[0]
    secret = data[:-padlen].decode('utf-8')

    logger.debug('Decryption successful')

    return secret
