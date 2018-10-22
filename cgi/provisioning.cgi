#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from __future__ import (absolute_import,
                        division,
                        print_function,
                        with_statement,
                        unicode_literals)

__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import sys
import cgi
import syslog

import totpcgi
import totpcgi.backends
import totpcgi.utils

import qrcode

from string import Template

try:
    from io import StringIO
except ImportError:
    # noinspection PyCompatibility
    from StringIO import StringIO

try:
    # noinspection PyCompatibility
    from urllib.parse import quote
except ImportError:
    from urllib import quote

import cgitb
cgitb.enable()

if len(sys.argv) > 1:
    # blindly assume it's the config file
    config_file = sys.argv[1]
else:
    config_file = '/etc/totpcgi/provisioning.conf'

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

cfg = ConfigParser.RawConfigParser()
cfg.read(config_file)

backends = totpcgi.backends.Backends()

try:
    backends.load_from_config(cfg)
except totpcgi.backends.BackendNotSupported as ex:
    syslog.syslog(syslog.LOG_CRIT,
                  'Backend engine not supported: %s' % ex)
    sys.exit(1)

syslog.openlog('provisioning.cgi', syslog.LOG_PID, syslog.LOG_AUTH)


def bad_request(config, why):
    templates_dir = config.get('secret', 'templates_dir')
    fh = open(os.path.join(templates_dir, 'error.html'))
    tpt = Template(fh.read())
    fh.close()

    vals = {
            'action_url':   config.get('secret', 'action_url'),
            'css_root':     config.get('secret', 'css_root'),
            'errormsg':     cgi.escape(why)
    }

    out = tpt.safe_substitute(vals)

    sys.stdout.write('Status: 400 BAD REQUEST\n')
    sys.stdout.write('Content-type: text/html\n')
    sys.stdout.write('Content-Length: %s\n' % len(out))
    sys.stdout.write('\n')

    sys.stdout.write(out)
    sys.exit(0)


def show_qr_code(data):
    qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=5,
            border=4)

    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image()

    fh = StringIO()
    img.save(fh)
    out = fh.getvalue()
    fh.close()

    sys.stdout.write('Status: 200 OK\n')
    sys.stdout.write('Content-type: image/png\n')
    sys.stdout.write('Content-Length: %s\n' % len(out))
    sys.stdout.write('Cache-Control: no-cache\n')
    sys.stdout.write('Pragma: no-cache\n')
    sys.stdout.write('Expires: -1\n')
    sys.stdout.write('\n')

    sys.stdout.write(out)
    sys.exit(0)


def show_login_form(config):
    templates_dir = config.get('secret', 'templates_dir')
    fh = open(os.path.join(templates_dir, 'login.html'))
    tpt = Template(fh.read())
    fh.close()

    vals = {
            'action_url':   config.get('secret', 'action_url'),
            'css_root':     config.get('secret', 'css_root')
    }

    out = tpt.safe_substitute(vals)
    
    sys.stdout.write('Status: 200 OK\n')
    sys.stdout.write('Content-type: text/html\n')
    sys.stdout.write('Content-Length: %s\n' % len(out))
    sys.stdout.write('\n')

    sys.stdout.write(out)
    sys.exit(0)


def show_reissue_page(config, user):
    templates_dir = config.get('secret', 'templates_dir')
    fh = open(os.path.join(templates_dir, 'reissue.html'))
    tpt = Template(fh.read())
    fh.close()

    vals = {
            'action_url':   config.get('secret', 'action_url'),
            'css_root':     config.get('secret', 'css_root'),
            'username':     user,
    }

    out = tpt.safe_substitute(vals)
    
    sys.stdout.write('Status: 200 OK\n')
    sys.stdout.write('Content-type: text/html\n')
    sys.stdout.write('Content-Length: %s\n' % len(out))
    sys.stdout.write('\n')

    sys.stdout.write(out)
    sys.exit(0)


def show_reissue_denied(config):
    syslog.syslog(syslog.LOG_NOTICE,
                  'Attempt to reissue token when token reissuance disabled')
    bad_request(config, "The ability to reissue tokens is currently disabled.")


def show_totp_page(config, user, gaus):
    # generate provisioning URI
    tpt = Template(config.get('secret', 'totp_user_mask'))
    try:
        totp_issuer = config.get('secret', 'totp_issuer')
    except ConfigParser.NoOptionError:
        totp_issuer = None
    totp_user = tpt.safe_substitute(username=user)

    totp_qr_uri = gaus.otp.provisioning_uri(totp_user, issuer_name=totp_issuer)

    action_url = config.get('secret', 'action_url')

    qrcode_embed = '<img src="%s?qrcode=%s"/>' % (action_url, quote(totp_qr_uri))

    templates_dir = config.get('secret', 'templates_dir')
    fh = open(os.path.join(templates_dir, 'totp.html'))
    tpt = Template(fh.read())
    fh.close()
    
    if gaus.scratch_tokens:
        scratch_tokens = '<br/>'.join(gaus.scratch_tokens)
    else:
        scratch_tokens = '&nbsp;'

    vals = {
            'action_url':     action_url,
            'css_root':       config.get('secret', 'css_root'),
            'qrcode_embed':   qrcode_embed,
            'scratch_tokens': scratch_tokens
    }

    out = tpt.safe_substitute(vals)

    sys.stdout.write('Status: 200 OK\n')
    sys.stdout.write('Content-type: text/html\n')
    sys.stdout.write('Content-Length: %s\n' % len(out))
    sys.stdout.write('Cache-Control: no-cache\n')
    sys.stdout.write('Pragma: no-cache\n')
    sys.stdout.write('Expires: -1\n')
    sys.stdout.write('\n')

    sys.stdout.write(out)
    sys.exit(0)


def generate_secret(config):
    encrypt_secret = config.getboolean('secret', 'encrypt_secret')
    window_size = config.getint('secret', 'window_size')
    rate_limit = config.get('secret', 'rate_limit')

    try:
        secret_bits = config.getint('secret', 'bits')
    except configparser.NoOptionError:
        secret_bits = 80

    # scratch tokens don't make any sense with encrypted secret
    if not encrypt_secret:
        scratch_tokens_n = config.getint('secret', 'scratch_tokens_n')
    else:
        scratch_tokens_n = 0

    (times, secs) = rate_limit.split(',')
    rate_limit = (int(times), int(secs))

    gaus = totpcgi.utils.generate_secret(rate_limit, window_size, 
                                         scratch_tokens_n, bs=secret_bits)

    return gaus


def cgimain():
    try:
        trust_http_auth = cfg.getboolean('secret', 'trust_http_auth')
    except configparser.NoOptionError:
        trust_http_auth = False

    form = cgi.FieldStorage()

    if 'qrcode' in form:
        if not trust_http_auth and os.environ['HTTP_REFERER'].find(os.environ['SERVER_NAME']) == -1:
            bad_request(cfg, 'Sorry, you failed the HTTP_REFERER check')

        qrc = form.getfirst('qrcode')
        show_qr_code(qrc)

    remote_host = os.environ['REMOTE_ADDR']

    if trust_http_auth and 'REMOTE_USER' in os.environ:
        user = os.environ['REMOTE_USER']
        if 'pincode' not in form:
            pincode = None
        else:
            pincode = form.getfirst('pincode')

        syslog.syslog(syslog.LOG_NOTICE,
                      'Using trust-http-auth for user=%s, host=%s' % (user, remote_host))

    else:
        must_keys = ('username', 'pincode')

        for must_key in must_keys:
            if must_key not in form:
                show_login_form(cfg)

        user = form.getfirst('username')
        pincode = form.getfirst('pincode')

        # start by verifying the pincode
        try:
            backends.pincode_backend.verify_user_pincode(user, pincode)
        except Exception as ex:
            syslog.syslog(syslog.LOG_NOTICE,
                          'Failure: user=%s, host=%s, message=%s' %
                          (user, remote_host, str(ex)))
            bad_request(cfg, str(ex))

        # pincode verified
        syslog.syslog(syslog.LOG_NOTICE,
                      'Success: user=%s, host=%s' % (user, remote_host))

    if 'action' in form:
        action = form.getfirst('action')
    else:
        action = 'issue'

    # is there an existing secret for this user?
    exists = True

    try:
        backends.secret_backend.get_user_secret(user, pincode)
    except totpcgi.UserNotFound as ex:
        # if we got it, then there isn't an existing secret in place
        exists = False
    except totpcgi.UserSecretError as ex:
        bad_request(cfg, 'Existing secret could not be processed: %s' % ex)

    try:
        allow_reissue = cfg.getboolean('secret', 'allow_reissue')
    except ConfigParser.NoOptionError:
        allow_reissue = True

    if exists and action != 'reissue':
        syslog.syslog(syslog.LOG_NOTICE,
                      'Secret exists: user=%s, host=%s' % (user, remote_host))
        # make sure we're allowed to reissue tokens
        if allow_reissue:
            show_reissue_page(cfg, user)
        else:
            show_reissue_denied(cfg)

    if action == 'reissue':
        # make sure we're allowed to reissue
        if not allow_reissue:
            show_reissue_denied(cfg)

        # verify token first
        tokencode = form.getfirst('tokencode')
        gau = totpcgi.GAUser(user, backends)

        try:
            gau.verify_token(tokencode, pincode)
        except Exception as ex:
            syslog.syslog(syslog.LOG_NOTICE,
                          'Token verify failed: user=%s, host=%s, message=%s' %
                          (user, remote_host, str(ex)))
            bad_request(cfg, 'Token verification failed: %s' % str(ex))

        # delete existing token
        try:
            backends.secret_backend.delete_user_secret(user)
        except Exception as ex:
            bad_request(cfg, 'Could not delete existing token for %s: %s' %
                        (user, str(ex)))

    # now generate the secret and store it
    gaus = generate_secret(cfg)

    # if we don't need to encrypt the secret, set pincode to None
    encrypt_secret = cfg.getboolean('secret', 'encrypt_secret')
    if not encrypt_secret:
        pincode = None

    backends.secret_backend.save_user_secret(user, gaus, pincode)

    # save new state
    backends.state_backend.get_user_state(user)
    state = totpcgi.GAUserState()
    backends.state_backend.update_user_state(user, state)

    show_totp_page(cfg, user, gaus)


if __name__ == '__main__':
    cgimain()
