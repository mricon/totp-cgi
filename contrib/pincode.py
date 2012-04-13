#!/usr/bin/python -tt

##
# Copyright (C) 2012 by Andrew Grimberg and contributors
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

"""
Create and manage a pincode file.
Pincodes can be any of any of the following crypt styles:

$1$  - MD5
$2a$ - Blowfish (requires py-bcrypt)
$5$  - SHA-256
$6$  - SHA-512 (default)
"""
import os
import sys
import argparse
import re
import crypt
import bcrypt
import hashlib
import getpass

SANE_USERNAME_RE = re.compile(r'([\w\.@=+_-]+)')

def genSalt():
    """
    Generate glibc2 compatible salt strings for use with $1$, $5$ or $6$
    crypt modes
    """

    random_data = os.urandom(256)
    hash = hashlib.md5(random_data).digest().encode('base64')
    alnum_hash = re.sub(r'[^a-zA-Z0-9./]', '', hash)
    return alnum_hash[:16]

def genPassword(method, password):
    """
    Generate the password with the appropriate crypt method
    """
    options = {
        'md5'   : '1',
        'sha256': '5',
        'sha512': '6',
    }

    if method == 'bcrypt':
        return bcrypt.hashpw(password, bcrypt.gensalt())
    else:
        return crypt.crypt(password, '$' + options[method] + '$' + genSalt() + '$')

if __name__ == '__main__':
    # Get our arguments
    parser = argparse.ArgumentParser(description="Manage pincode file")
    parser.add_argument('-p', '--passwd',
        help="The plaintext password to be encrypted and stored in the \
        file. This option should be used with extreme care as the \
        password will be clearly visible on the command line.")
    parser.add_argument('-c', '--create', action='store_true',
        help="Create the passwdfile. If passwdfile already exists, it \
        is rewritten and truncated")
    parser.add_argument('-m', '--method', nargs=1, default=['sha512'],
        choices = ['md5', 'bcrypt', 'sha256', 'sha512'],
        help="Select the crypt method to use for the password. \
        Defaults to sha512")
    parser.add_argument('-d', '--delete', '--del', action='store_true',
        help="Delete user. If the username exists in the specified \
        file, it will be deleted.")
    parser.add_argument('passwdfile',
        help="Name of the file to contain the username and password. \
        If -c is given, this file is created if it does not already \
        exist, or rewritten and truncated if it does exist.")
    parser.add_argument('username',
        help="The username to create or update in passwd file. If \
        username does not exist in this file, an entry will be added. \
        If it does exist, the password is changed.")
    args = parser.parse_args()

    if args.create:
        # Open and truncate the file
        try:
            fh = open(args.passwdfile, 'w+')
        except IOError, e:
            print >> sys.stderr, e.strerror + ' ' + e.filename
            sys.exit(e.errno)
    else:
        # Open the file for update (this only works if the file exists!)
        try:
            fh = open(args.passwdfile, 'r')
        except IOError, e:
            print >> sys.stderr, e.strerror + ' ' + e.filename
            sys.exit(e.errno)

    hashes = dict()

    # Read in the entire pincode file as a hash set for modification
    # this also has the (good) side effect of forcing usernames to be unique
    while True:
        line = fh.readline()
        if not line:
            break

        if line.find(':') == -1:
            continue

        line = line.strip()

        parts = line.split(':')
        hashes[parts[0]] = parts[1]

    # We're finished with our read in
    fh.close()

    # Are we deleting the user?
    if args.delete:
        try:
            hashes.pop(args.username)
        except KeyError:
            # if we get a KeyError they user likely doesn't exist
            # we're fine with this
            pass
    else:
        # Do we need to get the password from the user or was it passed?
        if args.passwd == None:
            # No password was passed in, prompt for a password
            passwd = getpass.getpass()
            if passwd == getpass.getpass('Verify Password: '):
                hashes[args.username] = genPassword(args.method[0], passwd)
            else:
                print >> sys.stderr, "Passwords do not match"
                sys.exit(1)
        else:
            # insert the user with the passed in password
            hashes[args.username] = genPassword(args.method[0], args.passwd)

    # We need to re-open (this time with a truncate) for the new write out
    try:
        fh = open(args.passwdfile, 'w')
    except IOError, e:
        print >> sys.stderr, e.strerror + ' ' . e.filename
        sys.exit(e.errno)

    for k, v in hashes.iteritems():
        print >> fh, "%s:%s" % (k, v)

    # Make sure we're a good citizen and close our filehandle
    fh.close()

# vim:sw=4:sts=4
