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
import cgi
import syslog
import logging

import cgitb
cgitb.enable()

import totpcgi
import totpcgi.backends

SECRETS_DIR  = '/etc/totpcgi/secrets'
STATE_DIR    = '/var/lib/totpcgi'
PAM_URL_CODE = 'OK'

syslog.openlog('totp.cgi', syslog.LOG_PID, syslog.LOG_AUTH)

def bad_request(why):
    output = 'ERR\n' + why + '\n'
    sys.stdout.write('Status: 400 BAD REQUEST\n')
    sys.stdout.write('Content-type: text/plain\n')
    sys.stdout.write('Content-Length: %s\n' % len(output))
    sys.stdout.write('\n')

    sys.stdout.write(output)
    sys.exit(0)

def cgimain():
    form = cgi.FieldStorage()

    must_keys = ('user', 'token', 'mode')

    for must_key in must_keys:
        if must_key not in form:
            bad_request("Missing field: %s" % must_key)

    user  = form.getfirst('user')
    token = form.getfirst('token')
    mode  = form.getfirst('mode')

    remote_host = os.environ['REMOTE_ADDR']

    if mode != 'PAM_SM_AUTH':
        bad_request('We only support PAM_SM_AUTH')

    state_be  = totpcgi.backends.GAStateBackendFile(STATE_DIR)
    secret_be = totpcgi.backends.GASecretBackendFile(SECRETS_DIR)

    ga = totpcgi.GoogleAuthenticator(secret_be, state_be)

    try:
        status = ga.verify_user_token(user, token)
    except Exception, ex:
        syslog.syslog(syslog.LOG_NOTICE,
            'Failure: user=%s, mode=%s, host=%s, message=%s' % (user, mode, 
                remote_host, str(ex)))
        bad_request(str(ex))

    syslog.syslog(syslog.LOG_NOTICE, 
        'Success: user=%s, mode=%s, host=%s, message=%s' % (user, mode, 
            remote_host, status))

    sys.stdout.write('Status: 200 OK\n')
    sys.stdout.write('Content-type: text/plain\n')
    sys.stdout.write('Content-Length: %s\n' % len(PAM_URL_CODE))
    sys.stdout.write('\n')

    sys.stdout.write(PAM_URL_CODE)


if __name__ == '__main__':
    cgimain()

