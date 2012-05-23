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
import totpcgi.utils

from string import Template

if len(sys.argv) > 1:
    # blindly assume it's the config file
    config_file = sys.argv[1]
else:
    config_file = '/etc/totpcgi/provisioning.conf'

import ConfigParser

config = ConfigParser.RawConfigParser()
config.read(config_file)

backends = totpcgi.backends.Backends()

try:
    backends.load_from_config(config)
except totpcgi.backends.BackendNotSupported, ex:
    syslog.syslog(syslog.LOG_CRIT, 
            'Backend engine not supported: %s' % ex)
    sys.exit(1)

syslog.openlog('provisioning.cgi', syslog.LOG_PID, syslog.LOG_AUTH)

def bad_request(why):
    #TODO: Make friendlier
    output = 'ERR\n' + why + '\n'
    sys.stdout.write('Status: 400 BAD REQUEST\n')
    sys.stdout.write('Content-type: text/plain\n')
    sys.stdout.write('Content-Length: %s\n' % len(output))
    sys.stdout.write('\n')

    sys.stdout.write(output)
    sys.exit(0)

def show_login_form(config):
    #TODO: CSRF token
    domain_title = config.get('main', 'domain_title')
    action_url   = config.get('main', 'action_url')

    tpt = Template('''
    <html>
        <head>
            <title>$domain_title</title>
        </head>
        <body>
        <h1>$domain_title</h1>
        <form id="login_form" name="login_form" action="$action_url" method="post">
            <p id="p_username">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username"/>
            </p>
            <p id="p_pincode">
                <label for="pincode">Pincode:</label>
                <input type="password" id="pincode" name="pincode"/>
            </p>
            <p id="p_submit">
                <input type="submit" value="Submit &raquo;"/>
            </p>
        </form>
        </body>
    </html>
    ''')

    out = tpt.safe_substitute(domain_title=domain_title, action_url=action_url)
    
    sys.stdout.write('Status: 200 OK\n')
    sys.stdout.write('Content-type: text/html\n')
    sys.stdout.write('Content-Length: %s\n' % len(out))
    sys.stdout.write('\n')

    sys.stdout.write(out)
    sys.exit(0)

def generate_secret(config):
    window_size = config.getint('main', 'window_size')
    rate_limit = config.get('main', 'rate_limit')
    scratch_tokens_n = config.get('main', 'scratch_tokens_n')

    (times, secs) = rate_limit.split(',')
    rate_limit = (int(times), int(secs))

    gaus = totpcgi.utils.generate_secret(rate_limit, window_size, 
        scratch_tokens_n)

    return gaus
    

def cgimain():
    form = cgi.FieldStorage()

    must_keys = ('username', 'pincode')

    for must_key in must_keys:
        if must_key not in form:
            show_login_form(config)

    user    = form.getfirst('username')
    pincode = form.getfirst('pincode')

    remote_host = os.environ['REMOTE_ADDR']

    # start by verifying the pincode
    try:
        backends.pincode_backend.verify_user_pincode(user, pincode)
    except Exception, ex:
        syslog.syslog(syslog.LOG_NOTICE,
            'Failure: user=%s, host=%s, message=%s' % (user, remote_host, 
                str(ex)))
        bad_request(str(ex))

    syslog.syslog(syslog.LOG_NOTICE, 
        'Success: user=%s, host=%s' % (user, remote_host)) 

    # pincode verified, now generate the secret and store it
    
    try:
        generate_secret(config)

        # if we don't need to encrypt the secret, set pincode to None
        encrypt_secret = config.getboolean('main', 'encrypt_secret')
        if not encrypt_secret:
            pincode = None

        backends.secret_backend.save_user_secret(user, gaus, pincode)

    except Exception, ex:
        syslog.syslog(syslog.LOG_NOTICE,
            'Failed to generate secret: user=%s, host=%s, message=%s' % (user, 
                remote_host, str(ex)))
        bad_request(str(ex))

    sys.stdout.write('Status: 200 OK\n')
    sys.stdout.write('Content-type: text/plain\n')
    sys.stdout.write('Content-Length: %s\n' % len(out))
    sys.stdout.write('\n')

    sys.stdout.write(out)


if __name__ == '__main__':
    cgimain()

