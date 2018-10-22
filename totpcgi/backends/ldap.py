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

import logging
import totpcgi
import totpcgi.backends

import ldap
from string import Template

logger = logging.getLogger('totpcgi')


class GASecretBackend:
    def __init__(self):
        raise totpcgi.backends.BackendNotSupported(
            'Secret backend not (yet?) supported by ldap backend engine')

    def get_user_secret(self, user):
        pass


class GAPincodeBackend(totpcgi.backends.GAPincodeBackend):
    """ This verifies the pincode by trying to bind to ldap using the 
        username and pincode passed for verification"""

    def __init__(self, ldap_url, ldap_dn, ldap_cacert):
        totpcgi.backends.GAPincodeBackend.__init__(self)

        logger.debug('Using LDAP Pincode backend')

        self.ldap_url = ldap_url
        self.ldap_dn = ldap_dn
        self.ldap_cacert = ldap_cacert

    def verify_user_pincode(self, user, pincode):
        if len(self.ldap_cacert):
            logger.debug('Setting ldap_cacert=%s', self.ldap_cacert)
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self.ldap_cacert)

        logger.debug('Connecting to ldap_url=%s', self.ldap_url)
        lconn = ldap.initialize(self.ldap_url)
        lconn.protocol_version = 3
        lconn.set_option(ldap.OPT_REFERRALS, 0)

        tpt = Template(self.ldap_dn)
        dn = tpt.safe_substitute(username=user)
        logger.debug('Attempting simple bind with dn=%s', dn)
        
        try:
            lconn.simple_bind_s(dn, pincode)

        except Exception as ex:
            raise totpcgi.UserPincodeError('LDAP bind failed: %s' % ex)

    def save_user_hashcode(self, user, pincode, makedb=True):
        raise totpcgi.backends.BackendNotSupported(
            'LDAP backend does not support saving pincodes.')

    def delete_user_hashcode(self, user):
        raise totpcgi.backends.BackendNotSupported(
            'LDAP backend does not support deleting pincodes.')


class GAStateBackend:
    def __init__(self):
        raise totpcgi.backends.BackendNotSupported(
            'State backend not supported by ldap backend engine')
