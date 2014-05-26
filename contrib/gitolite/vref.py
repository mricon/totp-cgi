#!/usr/bin/python -tt
__author__ = 'mricon'

import logging
import os
import sys
import anyjson

# default basic logger. We override it later.
logger = logging.getLogger(__name__)

# You need to change this to reflect your environment
GL_2FA_COMMAND = 'ssh git@gitolite.kernel.org 2fa'
HELP_DOC_LINK = 'https://example.com'

# Set this to "pass" to allow opt-in 2fa authentication
MISSING_SECRET = 'fail'


def gl_fail_exit():
    sys.stdout.write('%s: 2-factor verification failed\n' % sys.argv[7])
    sys.exit(1)


def print_help_link():
    print
    print('If you need more help, please see the following link:')
    print('    %s' % HELP_DOC_LINK)
    print


def how_to_enroll():
    print('You need to enroll with our 2-factor authentication setup before you can push')
    print_help_link()


def how_to_validate():
    print('Please get your 2-factor authentication token and run:')
    print('    %s val [token]' % GL_2FA_COMMAND)
    print_help_link()


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
        if MISSING_SECRET == 'pass':
            logger.info('User not enrolled with 2fa, allowing to proceed.')
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

    logger.info('Checking if %s has been previously validated' % remote_ip)

    # First compare as strings, as this is much faster
    matching = None
    if remote_ip not in authorized_ips.keys():
        import netaddr
        # We can't rely on strings, as ipv6 has more than one way to represent the same IP address, e.g.:
        # 2001:4f8:1:10:0:1991:8:25 and 2001:4f8:1:10::1991:8:25
        for authorized_ip in authorized_ips.keys():
            if netaddr.IPAddress(remote_ip) == netaddr.IPAddress(authorized_ip):
                # Found it
                matching = authorized_ip
                break
    else:
        matching = remote_ip

    if matching is None:
        logger.critical('IP address "%s" has not been validated.' % remote_ip)
        how_to_validate()
        gl_fail_exit()

    # Okay, but is it still valid?
    expires = authorized_ips[matching]['expires']
    logger.debug('Validation for %s expires on %s' % (matching, expires))
    import datetime
    import dateutil, dateutil.parser

    exp_time = dateutil.parser.parse(expires)
    utc = dateutil.tz.tzutc()
    now_time = datetime.datetime.now(utc)
    logger.debug('exp_time: %s' % exp_time)
    logger.debug('now_time: %s' % now_time)

    if now_time > exp_time:
        logger.critical('Validation for IP address %s has expired.' % matching)
        how_to_validate()
        gl_fail_exit()

    logger.info('Successfully validated remote IP %s' % matching)


if __name__ == '__main__':
    if 'GL_USER' not in os.environ:
        sys.stderr.write('Please run me from gitolite hooks')
        sys.exit(1)

    if 'SSH_CONNECTION' not in os.environ:
        sys.stderr.write('This only works when accessed over SSH')
        sys.exit(1)

    vref_verify()
    sys.exit(0)