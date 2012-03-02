#!/usr/bin/python -tt
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
