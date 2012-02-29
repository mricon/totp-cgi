#!/usr/bin/python -tt
import os
import sys
import cgi
import syslog
import logging

import cgitb
cgitb.enable()

import totpcgi

SECRETS_DIR = '/var/lib/totpcgi/secrets'
STATUS_DIR  = '/var/lib/totpcgi/status'

syslog.openlog('totp.cgi', logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)

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

    ga = totpcgi.GoogleAuthenticator(SECRETS_DIR, STATUS_DIR)

    try:
        status = ga.verify_user_token(user, token)
    except Exception, ex:
        syslog.syslog(syslog.LOG_NOTICE,
            'Failure: user=%s, mode=%s, host=%s, message=%s' % (user, mode, 
                remote_host, ex.message))
        bad_request(ex.message)

    syslog.syslog(syslog.LOG_NOTICE, 
        'Success: user=%s, mode=%s, host=%s, message=%s' % (user, mode, 
            remote_host, status))

    sys.stdout.write('Status: 200 OK\n')
    sys.stdout.write('Content-type: text/plain\n')
    sys.stdout.write('Content-Length: %s\n' % len(status))
    sys.stdout.write('\n')

    sys.stdout.write('OK\n')
    sys.stdout.write(status)


if __name__ == '__main__':
    cgimain()

