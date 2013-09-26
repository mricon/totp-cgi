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

import os
import sys

from optparse import OptionParser
import ConfigParser

import totpcgi
import totpcgi.backends
import totpcgi.utils

import getpass

import syslog
syslog.openlog('totpprov', syslog.LOG_PID, syslog.LOG_AUTH)

from string import Template

def ays():
    ays = raw_input('Are you sure [y/N]: ')
    if ays != 'y':
        print 'Exiting on user command'
        sys.exit(0)

def ask_for_new_pincode():
    pincode = None
    while pincode is None:
        pincode = getpass.getpass('Pincode: ')
        if pincode != getpass.getpass('Verify: '):
            print 'Pincodes did not match'
            pincode = None

    return pincode

def ask_for_user_pincode(backends, user):
    pincode = None
    while pincode is None:
        pincode = getpass.getpass('Pincode for user %s: ' % user)
        try:
            backends.pincode_backend.verify_user_pincode(user, pincode)
        except totpcgi.UserPincodeError:
            print 'Pincode failed to verify.'
            pincode = None

    return pincode


def generate_secret(config):
    encrypt_secret = config.getboolean('secret', 'encrypt_secret')
    window_size = config.getint('secret', 'window_size')
    rate_limit = config.get('secret', 'rate_limit')

    # scratch tokens don't make any sense with encrypted secret
    if not encrypt_secret:
        scratch_tokens_n = config.getint('secret', 'scratch_tokens_n')
    else:
        scratch_tokens_n = 0

    (times, secs) = rate_limit.split(',')
    rate_limit = (int(times), int(secs))

    gaus = totpcgi.utils.generate_secret(rate_limit, window_size, 
        scratch_tokens_n)

    return gaus

def delete_user(backends, config, args):
    backends.secret_backend.delete_user_secret(args[1])
    backends.pincode_backend.delete_user_hashcode(args[1])
    backends.state_backend.delete_user_state(args[1])

    print 'User %s deleted' % args[1]

def delete_user_state(backends, config, args):
    backends.state_backend.delete_user_state(args[1])
    print 'State data for user %s deleted' % args[1]

def delete_user_pincode(backends, config, args):
    backends.pincode_backend.delete_user_hashcode(args[1])
    print 'Pincode for user %s deleted' % args[1]

def delete_user_secret(backends, config, args):
    backends.secret_backend.delete_user_secret(args[1])
    print 'Google authenticator token for user %s deleted' % args[1]

def set_user_pincode(backends, config, args):
    usehash = config.get('pincode', 'usehash')
    makedb  = config.getboolean('pincode', 'makedb')

    pincode  = ask_for_new_pincode()
    hashcode = totpcgi.utils.hash_pincode(pincode, usehash)

    backends.pincode_backend.save_user_hashcode(args[1], hashcode, makedb)
    print 'Pincode for user %s set, verifying.' % args[1]

    backends.pincode_backend.verify_user_pincode(args[1], pincode)
    print 'Verified successfully.'

    return pincode

def encrypt_user_token(backends, config, args):
    user = args[1]
    # see if it's already encrypted
    try:
        gaus = backends.secret_backend.get_user_secret(user)
    except totpcgi.UserNotFound, ex:
        print 'Error: No existing tokens found for user %s' % user
        sys.exit(1)
    except totpcgi.UserSecretError, ex:
        print 'Error: the token for user %s is already encrypted' % user
        sys.exit(1)

    pincode = ask_for_user_pincode(backends, user)

    backends.secret_backend.save_user_secret(user, gaus, pincode)
    print 'Successfully encrypted user secret'

def decrypt_user_token(backends, config, args):
    user = args[1]
    pincode = getpass.getpass('Pincode for user %s: ' % user)

    # Try getting the user secret
    try:
        gaus = backends.secret_backend.get_user_secret(user, pincode)
    except totpcgi.UserNotFound, ex:
        print 'Error: No existing tokens found for user %s' % user
        sys.exit(1)
    except totpcgi.UserSecretError, ex:
        print 'Error: Could not decrypt the secret for user %s' % user
        sys.exit(1)

    backends.secret_backend.save_user_secret(user, gaus, None)
    print 'Successfully decrypted user secret'

def generate_user_token(backends, config, args, pincode=None):
    user = args[1]
    
    try:
        try:
            gaus = backends.secret_backend.get_user_secret(user)
        except totpcgi.UserSecretError:
            pass

        print 'Existing token found for user %s. Delete it first.' % user
        sys.exit(1)

    except totpcgi.UserNotFound, ex:
        pass

    gaus = generate_secret(config)

    # if we don't need to encrypt the secret, set pincode to None
    encrypt_secret = config.getboolean('secret', 'encrypt_secret')
    if encrypt_secret:
        if pincode is None:
            pincode = ask_for_user_pincode(backends, user)

    backends.secret_backend.save_user_secret(user, gaus, pincode)

    # purge all old state, as it's now obsolete
    backends.state_backend.delete_user_state(user)

    print 'New token generated for user %s' % user
    # generate provisioning URI
    tpt = Template(config.get('secret', 'totp_user_mask'))
    totp_user = tpt.safe_substitute(username=user)
    totp_qr_uri = gaus.totp.provisioning_uri(totp_user)
    print gaus.totp.provisioning_uri(totp_user)

    if gaus.scratch_tokens:
        print 'Scratch tokens:'
        print '\n'.join(gaus.scratch_tokens)

def provision_user(backends, config, args):
    user = args[1]

    try:
        try:
            gaus = backends.secret_backend.get_user_secret(user)
        except totpcgi.UserSecretError:
            pass

        print 'Existing data found for user %s. Delete it first.' % user
        sys.exit(1)

    except totpcgi.UserNotFound, ex:
        pass

    pincode = set_user_pincode(backends, config, args)
    encrypt_secret = config.getboolean('secret', 'encrypt_secret')
    if not encrypt_secret:
        pincode = None

    generate_user_token(backends, config, args, pincode)

if __name__ == '__main__':
    usage = '''usage: %prog [-c provisioning.conf] command username
    Use this tool to provision totpcgi users and tokens. See manpage
    for more info on commands.
    '''

    parser = OptionParser(usage=usage, version='0.1')
    parser.add_option('-c', '--config', dest='config_file', 
            default='/etc/totpcgi/provisioning.conf',
            help='Path to provisioning.conf (%default)')

    (opts, args) = parser.parse_args()

    config = ConfigParser.RawConfigParser()
    config.read(opts.config_file)

    backends = totpcgi.backends.Backends()

    try:
        backends.load_from_config(config)
    except totpcgi.backends.BackendNotSupported, ex:
        syslog.syslog(syslog.LOG_CRIT, 
                'Backend engine not supported: %s' % ex)
        sys.exit(1)
    
    if not args:
        parser.error('Must specify command')

    command = args[0]

    if command == 'delete-user':
        print 'Deleting user %s' % args[1]
        ays()
        delete_user(backends, config, args)

    elif command == 'delete-user-state':
        print 'Deleting state data for user %s' % args[1]
        ays()
        delete_user_state(backends, config, args)

    elif command == 'delete-user-pincode':
        print 'Deleting pincode for user %s' % args[1]
        ays()
        delete_user_pincode(backends, config, args)

    elif command == 'delete-user-token':
        print 'Deleting token data for user %s' % args[1]
        ays()
        delete_user_secret(backends, config, args)

    elif command == 'set-user-pincode':
        print 'Setting pincode for user %s' % args[1]
        ays()
        set_user_pincode(backends, config, args)

    elif command == 'encrypt-user-token':
        print 'Encrypting user token for %s' % args[1]
        ays()
        encrypt_user_token(backends, config, args)

    elif command == 'decrypt-user-token':
        print 'Decrypting user token for %s' % args[1]
        ays()
        decrypt_user_token(backends, config, args)

    elif command == 'generate-user-token':
        print 'Generating new token for user %s' % args[1]
        ays()
        generate_user_token(backends, config, args)

    elif command == 'provision-user':
        print 'Provisioning new TOTP user %s' % args[1]
        ays()
        provision_user(backends, config, args)

    else:
        parser.error('Unknown command: %s' % command)

