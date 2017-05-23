#!/usr/bin/python -tt
__author__ = 'mricon'

import logging
import os
import sys
import anyjson
import netaddr

import datetime
import dateutil
import dateutil.parser
import dateutil.tz

#--------------- CHANGE ME TO REFLECT YOUR ENVIRONMENT -------------------

# What should people run to invoke the 2fa command?
GL_2FA_COMMAND = 'ssh git@example.com 2fa'
# Where does helpful documentation live?
HELP_DOC_LINK = 'https://example.com'

#-------------------------------------------------------------------------

# default basic logger. We override it later.
logger = logging.getLogger(__name__)


def gl_fail_exit():
    sys.stdout.write('%s: 2-factor verification failed\n' % sys.argv[7])
    sys.exit(1)


def print_help_link():
    print
    print('If you need more help, please see the following link:')
    print('    %s' % HELP_DOC_LINK)
    print


def how_to_enroll():
    print('You will need to enroll with 2-factor authentication')
    print('before you can push to this repository.')
    print_help_link()


def how_to_validate():
    print('Please get your 2-factor authentication token and run:')
    print('    %s val [token]' % GL_2FA_COMMAND)
    print_help_link()


def is_expired(expires):
    exp_time = dateutil.parser.parse(expires)
    utc = dateutil.tz.tzutc()
    now_time = datetime.datetime.now(utc)
    logger.debug('exp_time: %s' % exp_time)
    logger.debug('now_time: %s' % now_time)

    if now_time > exp_time:
        logger.debug('Validation expired')
        return True

    return False


def is_authorized_ip(ip, authorized_ips):
    # Since authorized_ips can list both ips and networks,
    # we always use network-aware matching
    myipaddr = netaddr.IPAddress(ip)
    matched = False
    for authorized_ip in authorized_ips.keys():
        if myipaddr in netaddr.IPNetwork(authorized_ip):
            # Do we have a session restriction?
            if 'sessionid' in authorized_ips[authorized_ip]:
                if 'XDG_SESSION_ID' not in os.environ:
                    # not sure what happened but this invalidates the session
                    logger.critical('Could not obtain session info from env.')
                    return False
                if os.environ['XDG_SESSION_ID'] != authorized_ips[authorized_ip]['sessionid']:
                    logger.critical('Your session for IP address %s has changed.' % ip)
                    logger.critical('Check your ControlMaster settings and run val-session again.')
                    return False
            matched = True
            # Is it expired?
            expires = authorized_ips[authorized_ip]['expires']
            if not is_expired(expires):
                return True

    if not matched:
        logger.critical('IP address "%s" has not been validated.' % ip)
    else:
        logger.critical('Validation for IP address %s has expired.' % ip)

    return False


def load_authorized_ips():
    # The authorized ips file has the following structure:
    # {
    #   'IP_ADDR': {
    #       'added': RFC_8601_DATETIME,
    #       'expires': RFC_8601_DATETIME,
    #       'whois': whois information about the IP at the time of recording,
    #       'geoip': geoip information about the IP at the time of recording,
    #  }
    #
    # It is stored in GL_ADMIN_BASE/2fa/validations/GL_USER.js
    valfile = os.path.join(
        os.environ['GL_ADMIN_BASE'], '2fa/validations', '%s.js' % os.environ['GL_USER'])

    logger.debug('Loading authorized ips from %s' % valfile)
    valdata = {}
    if os.access(valfile, os.R_OK):
        try:
            fh = open(valfile, 'r')
            jdata = fh.read()
            fh.close()
            valdata = anyjson.deserialize(jdata)
        except:
            logger.critical('Validations file exists, but could not be parsed!')
            logger.critical('Please rerun "2fa val" to create a new file!')
            gl_fail_exit()

    return valdata


def vref_verify():
    global logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "[%s] " % os.environ['GL_USER'] + "%(asctime)s - %(levelname)s - %(message)s")

    # We log alongside GL_LOGFILE and follow Gitolite's log structure
    (logdir, logname) = os.path.split(os.environ['GL_LOGFILE'])
    logfile = os.path.join(logdir, '2fa-vref-%s' % logname)
    ch = logging.FileHandler(logfile)
    ch.setFormatter(formatter)

    if '2FA_LOG_DEBUG' in os.environ.keys():
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    ch.setLevel(loglevel)
    logger.addHandler(ch)

    # only critical notices to the console
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    ch.setLevel(logging.CRITICAL)
    logger.addHandler(ch)

    # Check if this person has a token issued
    # The token files are stored in GL_ADMIN_BASE/2fa/secrets/GL_USER.totp
    secret_file = os.path.join(
        os.environ['GL_ADMIN_BASE'], '2fa/secrets',
        '%s.totp' % os.environ['GL_USER'])

    if not os.path.exists(secret_file):
        # See if we were called as "VREF/2fa/optin"
        if sys.argv[7][-6:] == '/optin':
            logger.info('User not enrolled with 2fa, but /optin is set. Allowing the push.')
            sys.exit(0)
        else:
            logger.critical('User not enrolled with 2-factor authentication.')
            how_to_enroll()
            gl_fail_exit()

    # SSH_CONNECTION format is: "REMOTE_IP REMOTE_PORT LOCAL_IP LOCAL_PORT"
    # We only care about the first entry
    chunks = os.environ['SSH_CONNECTION'].split()

    remote_ip = chunks[0]
    authorized_ips = load_authorized_ips()

    logger.debug('Checking if %s has been previously validated' % remote_ip)

    if not is_authorized_ip(remote_ip, authorized_ips):
        how_to_validate()
        gl_fail_exit()

    logger.info('Remote IP %s is valid' % remote_ip)


if __name__ == '__main__':
    if 'GL_USER' not in os.environ:
        sys.stderr.write('Please run me from gitolite hooks')
        sys.exit(1)

    if 'SSH_CONNECTION' not in os.environ:
        sys.stderr.write('This only works when accessed over SSH')
        sys.exit(1)

    vref_verify()
    sys.exit(0)
