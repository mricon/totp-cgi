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
import getpass

from totpcgi.utils import hash_pincode
from totpcgi.backends.file import GAPincodeBackend

if __name__ == '__main__':
    # Get our arguments
    parser = argparse.ArgumentParser(description="Manage pincode file")
    parser.add_argument('-p', '--passwd',
        help="The plaintext password to be encrypted and stored in the \
        file. This option should be used with extreme care as the \
        password will be clearly visible on the command line.")
    parser.add_argument('-m', '--method', nargs=1, default=['sha512'],
        choices = ['md5', 'bcrypt', 'sha256', 'sha512'],
        help="Select the crypt method to use for the password. \
        Defaults to sha512")
    parser.add_argument('-b', '--makedb', action='store_true',
        help="Compile a binary database after writing the file.")
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

    gapb = GAPincodeBackend(args.passwdfile)

    # Are we deleting the user?
    if args.delete:
        gapb.delete_user_hashcode(args.username)
        sys.exit(0)

    # Do we need to get the password from the user or was it passed?
    if args.passwd == None:
        # No password was passed in, prompt for a password
        passwd = getpass.getpass()
        if passwd != getpass.getpass('Verify Password: '):
            print >> sys.stderr, "Passwords do not match"
            sys.exit(1)
    else:
        # insert the user with the passed in password
        passwd = args.passwd

    hashcode = hash_pincode(passwd, args.method[0])
    gapb.save_user_hashcode(args.username, hashcode, args.makedb)

# vim:sw=4:sts=4
