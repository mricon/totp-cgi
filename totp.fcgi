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
from flup.server import fcgi
from cgi import parse_qs
import syslog

import totpcgi
import totpcgi.backends

SECRETS_DIR  = '/etc/totpcgi/secrets'
STATE_DIR    = '/var/lib/totpcgi'
PAM_URL_CODE = 'OK'

syslog.openlog('totp.fcgi', syslog.LOG_PID, syslog.LOG_AUTH)

def bad_request(start_response, why):
    output = 'ERR\n' + why + '\n'
    start_response('400 BAD REQUEST', [('Content-Type', 'text/plain'),
                                       ('Content-Length', str(len(output)))])
    return output

def webapp(environ, start_response):
    if environ['REQUEST_METHOD'] != 'POST':
        return bad_request(start_response, "Missing post data")

    rq_len = int(environ.get('CONTENT_LENGTH', 0))
    rq_data = environ['wsgi.input'].read(rq_len)

    form = parse_qs(rq_data)

    must_keys = ('user', 'token', 'mode')

    for must_key in must_keys:
        if must_key not in form.keys():
            return bad_request(start_response, "Missing field: %s" % must_key)

    user  = form['user'][0]
    token = form['token'][0]
    mode  = form['mode'][0]

    remote_host = environ.get('REMOTE_ADDR')

    if mode != 'PAM_SM_AUTH':
        return bad_request(start_response, "We only support PAM_SM_AUTH")

    state_be  = totpcgi.backends.GAStateBackendFile(STATE_DIR)
    secret_be = totpcgi.backends.GASecretBackendFile(SECRETS_DIR)

    ga = totpcgi.GoogleAuthenticator(secret_be, state_be)

    try:
        status = ga.verify_user_token(user, token)
    except Exception, ex:
        syslog.syslog(syslog.LOG_NOTICE,
            'Failure: user=%s, mode=%s, host=%s, message=%s' % (user, mode, 
                remote_host, str(ex)))
        return bad_request(start_response, str(ex))

    syslog.syslog(syslog.LOG_NOTICE, 
        'Success: user=%s, mode=%s, host=%s, message=%s' % (user, mode, 
            remote_host, status))

    status = PAM_URL_CODE

    start_response('200 OK', [('Content-type', 'text/plain'),
                              ('Content-Length', str(len(status)))])

    return status


fcgi.WSGIServer(webapp).run()
