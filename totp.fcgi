#!/usr/bin/python -tt
from flup.server import fcgi
from cgi import parse_qs
import syslog
import logging
import ConfigParser

import totpcgi

SECRETS_DIR = '/var/lib/totpcgi/secrets'
STATUS_DIR  = '/var/lib/totpcgi/status'

syslog.openlog('totp.fcgi', logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)

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

    ga = totpcgi.GoogleAuthenticator(SECRETS_DIR, STATUS_DIR)

    try:
        status = ga.verify_user_token(user, token)
    except Exception, ex:
        syslog.syslog(syslog.LOG_NOTICE,
            'Failure: user=%s, mode=%s, host=%s, message=%s' % (user, mode, 
                remote_host, ex.message))
        return bad_request(start_response, ex.message)

    syslog.syslog(syslog.LOG_NOTICE, 
        'Success: user=%s, mode=%s, host=%s, message=%s' % (user, mode, 
            remote_host, status))

    start_response('200 OK', [('Content-type', 'text/plain'),
                              ('Content-Length', str(len(status)))])
    #
    # pam_url wants to see a PSK
    return status



fcgi.WSGIServer(webapp).run()
