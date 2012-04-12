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

    def __init__(self, ldap_url, ldap_dn):
        totpcgi.backends.GAPincodeBackend.__init__(self)
        self.ldap_url = ldap_url
        self.ldap_dn = ldap_dn

    def verify_user_pincode(self, user, pincode):
        lconn = ldap.initialize(self.ldap_url)
        lconn.protocol_version = 3
        lconn.set_option(ldap.OPT_REFERRALS, 0)

        tpt = Template(self.ldap_dn)
        dn = tpt.safe_substitute(username=user)
        
        try:
            lconn.simple_bind(dn, pincode)

        except ldap.LDAPError, ex:
            raise totpcgi.UserPincodeError('LDAP bind failed: %s' % ex)

class GAStateBackend:
    def __init__(self):
        raise totpcgi.backends.BackendNotSupported(
                'State backend not supported by ldap backend engine')

