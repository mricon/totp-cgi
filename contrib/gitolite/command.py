#!/usr/bin/python -tt
__author__ = 'mricon'

import logging
import os
import sys
import anyjson

import totpcgi
import totpcgi.backends
import totpcgi.backends.file
import totpcgi.utils

import datetime
import dateutil
import dateutil.parser
import dateutil.tz

import netaddr

from string import Template

import syslog

#--------------- CHANGE ME TO REFLECT YOUR ENVIRONMENT -------------------

# You need to change this to reflect your environment
GL_2FA_COMMAND = 'ssh git@example.com 2fa'
HELP_DOC_LINK = 'https://example.com'

# Set to False to disallow yubikey (HOTP) enrolment
ALLOW_YUBIKEY = True

# This will allow anyone to use "override" as the 2-factor token
# Obviously, this should only be used during initial debugging
# and testing and then set to false.
ALLOW_BYPASS_OVERRIDE = False

# In the TOTP case, the window size is the time drift between the user's device
# and the server. A window size of 17 means 17*10 seconds, or in other words,
# we'll accept any tokencodes that were valid within 170 seconds before now, and
# 170 seconds after now.
# In the HOTP case, discrepancy between the counter on the device and the counter
# on the server is virtually guaranteed (accidental button presses on the yubikey,
# authentication failures, etc), so the window size indicates how many tokens we will
# try in addition to the current one. The setting of 30 is sane and is not likely to
# lock someone out.
TOTP_WINDOW_SIZE = 17
HOTP_WINDOW_SIZE = 30

# First value is the number of times. Second value is the number of seconds.
# So, "3, 30" means "3 falures within 30 seconds"
RATE_LIMIT = (3, 30)

# Google Authenticator and other devices default to key length of 80 bits, while
# for yubikeys the length must be 160 bits. I suggest you leave these as-is.
TOTP_KEY_LENGTH = 80
HOTP_KEY_LENGTH = 160

# This identifies the token in the user's TOTP app
TOTP_USER_MASK = '$username@example.com'

# GeoIP-city database location.
# This is only currently used as a sort of a reminder to the users, so when they list
# their current validations using list-val, it can help them figure out where they
# previously authorized from.
# You can download the City database from
# http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.xz and put
# into GL_ADMIN_BASE/2fa/ (uncompress first). If the code doesn't find it, it'll
# try to use the basic GeoIP country information. If that fails, it'll just
# quitely omit GeoIP data.
GEOIP_CITY_DB = os.path.join(os.environ['GL_ADMIN_BASE'], '2fa/GeoLiteCity.dat')

# Identify ourselves in syslog as "gl-2fa"
syslog.openlog('gl-2fa', syslog.LOG_PID, syslog.LOG_AUTH)

# When allowing networks via val-subnet, this is the maximum network size
# to allow (CIDR style, meaning /24, /16, etc)
# E.g. MAX_CIDR_SIZE = 12 means we will not allow x.x.0.0/11, but /13 is ok
MAX_CIDR_SIZE = 12

#-------------------------------------------------------------------------

# default basic logger. We override it later.
logger = logging.getLogger(__name__)


def print_help_link():
    print('')
    print('If you need more help, please see the following link:')
    print('    %s' % HELP_DOC_LINK)
    print('')


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
    for authorized_ip in authorized_ips.keys():
        if myipaddr in netaddr.IPNetwork(authorized_ip):
            # Do we have a session restriction?
            if 'sessionid' in authorized_ips[authorized_ip]:
                if 'XDG_SESSION_ID' not in os.environ:
                    # not sure what happened but this invalidates the session
                    return False
                if os.environ['XDG_SESSION_ID'] != authorized_ips[authorized_ip]['sessionid']:
                    # Your ControlMaster session got renewed, sorry!
                    return False
            # Is it expired?
            expires = authorized_ips[authorized_ip]['expires']
            if not is_expired(expires):
                return True

    return False


def get_geoip_crc(ipaddr):
    import GeoIP

    if os.path.exists(GEOIP_CITY_DB):
        logger.debug('Opening geoip db in %s' % GEOIP_CITY_DB)
        gi = GeoIP.open(GEOIP_CITY_DB, GeoIP.GEOIP_STANDARD)
    else:
        logger.debug('%s does not exist, using basic geoip db' % GEOIP_CITY_DB)
        gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)

    ginfo = gi.record_by_addr(ipaddr)

    if ginfo is not None:
        city = region_name = country_code = 'Unknown'

        if ginfo['city'] is not None:
            city = unicode(ginfo['city'], 'iso-8859-1')
        if ginfo['region_name'] is not None:
            region_name = unicode(ginfo['region_name'], 'iso-8859-1')
        if ginfo['country_code'] is not None:
            country_code = unicode(ginfo['country_code'], 'iso-8859-1')

        crc = u'%s, %s, %s' % (city, region_name, country_code)

    else:
        # try just the country code, then
        crc = gi.country_code_by_addr(ipaddr)
        if not crc:
            return None
        crc = unicode(crc, 'iso-8859-1')

    return crc


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

    user = os.environ['GL_USER']
    val_dir = os.path.join(os.environ['GL_ADMIN_BASE'], '2fa/validations')
    if not os.path.exists(val_dir):
        os.makedirs(val_dir, 0700)
        logger.debug('Created val_dir in %s' % val_dir)

    valfile = os.path.join(val_dir, '%s.js' % user)

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
            logger.critical('All previous validations have been lost, starting fresh.')
    return valdata


def store_authorized_ips(valdata):
    user = os.environ['GL_USER']
    val_dir = os.path.join(os.environ['GL_ADMIN_BASE'], '2fa/validations')
    valfile = os.path.join(val_dir, '%s.js' % user)
    jdata = anyjson.serialize(valdata)
    fh = open(valfile, 'w')
    fh.write(jdata)
    fh.close()
    logger.debug('Wrote new validations file in %s' % valfile)


def store_validation(validated_ip, hours, session):
    valdata = load_authorized_ips()

    # Get rid of any previously validated IPs matching this one (or this range)
    mynetwork = netaddr.IPNetwork(validated_ip)
    for authorized_ip in valdata.keys():
        if netaddr.IPNetwork(authorized_ip) in mynetwork:
            del valdata[authorized_ip]

    utc = dateutil.tz.tzutc()
    now_time = datetime.datetime.now(utc).replace(microsecond=0)
    expires = now_time + datetime.timedelta(hours=hours)

    valdata[validated_ip] = {
        'added': now_time.isoformat(sep=' '),
        'expires': expires.isoformat(sep=' '),
    }

    # if val-session was used, we store the current XDG_SESSION_ID, if found
    # otherwise it's effectively equivalent to 'val'
    if session and 'XDG_SESSION_ID' in os.environ:
        xdg_session_id = os.environ['XDG_SESSION_ID']
        valdata[validated_ip]['sessionid'] = xdg_session_id
        logger.info('Adding IP address %s with sessionid %s until %s'
                % (validated_ip, xdg_session_id, expires.strftime('%c %Z')))
    else:
        logger.info('Adding IP address %s until %s' % (validated_ip, expires.strftime('%c %Z')))

    if mynetwork.size == 1:
        # Try to lookup whois info if cymruwhois is available
        try:
            import cymruwhois
            cym = cymruwhois.Client()
            res = cym.lookup(validated_ip)
            if res.owner and res.cc:
                whois = "%s/%s\n" % (res.owner, res.cc)
                valdata[validated_ip]['whois'] = whois
                logger.info('Whois information for %s: %s' % (validated_ip, whois))
        except:
            pass

        try:
            geoip = get_geoip_crc(validated_ip)
            if geoip is not None:
                valdata[validated_ip]['geoip'] = geoip
                logger.info('GeoIP information for %s: %s' % (validated_ip, geoip))
        except:
            pass

    store_authorized_ips(valdata)


def generate_user_token(backends, mode):
    if mode == 'totp':
        gaus = totpcgi.utils.generate_secret(
            RATE_LIMIT, TOTP_WINDOW_SIZE, 5, bs=TOTP_KEY_LENGTH)

    else:
        gaus = totpcgi.utils.generate_secret(
            RATE_LIMIT, HOTP_WINDOW_SIZE, 5, bs=HOTP_KEY_LENGTH)
        gaus.set_hotp(0)

    user = os.environ['GL_USER']
    backends.secret_backend.save_user_secret(user, gaus, None)
    # purge all old state, as it's now obsolete
    backends.state_backend.delete_user_state(user)

    logger.info('New token generated for user %s' % user)
    remote_ip = os.environ['SSH_CONNECTION'].split()[0]
    syslog.syslog(
        syslog.LOG_NOTICE,
        'Enrolled: user=%s, host=%s, mode=%s' % (user, remote_ip, mode)
    )

    if mode == 'totp':
        # generate provisioning URI
        tpt = Template(TOTP_USER_MASK)
        totp_user = tpt.safe_substitute(username=user)
        qr_uri = gaus.otp.provisioning_uri(totp_user)
        import urllib
        print('')
        print('Please make sure "qrencode" is installed.')
        print('Run the following commands to display your QR code:')
        print('    unset HISTFILE')
        print('    qrencode -tANSI -m1 -o- "%s"' % qr_uri)
        print('')
        print('If that does not work or if you do not have access to')
        print('qrencode or a similar QR encoding tool, then you may')
        print('open an INCOGNITO/PRIVATE MODE window in your browser')
        print('and paste the following URL:')
        print(
            'https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=%s' %
            urllib.quote_plus(qr_uri))
        print('')
        print('Scan the resulting QR code with your TOTP app, such as')
        print('FreeOTP (recommended), Google Authenticator, Authy, or others.')

    else:
        import binascii
        import base64
        keyhex = binascii.hexlify(base64.b32decode(gaus.otp.secret))
        print('')
        print('Please make sure "ykpersonalize" has been installed.')
        print('Insert your yubikey and, as root, run the following command')
        print('to provision the secret into slot 1 (use -2 for slot 2):')
        print('    unset HISTFILE')
        print('    ykpersonalize -1 -ooath-hotp -oappend-cr -a%s' % keyhex)
        print('')

    if gaus.scratch_tokens:
        print('Please write down/print the following 8-digit scratch tokens.')
        print('If you lose your device or temporarily have no access to it, you')
        print('will be able to use these tokens for one-time bypass.')
        print('')
        print('Scratch tokens:')
        print('\n'.join(gaus.scratch_tokens))

    print

    print('Now run the following command to verify that all went well')

    if mode == 'totp':
        print('    %s val [token]' % GL_2FA_COMMAND)
    else:
        print('    %s val [yubkey button press]' % GL_2FA_COMMAND)

    print_help_link()


def enroll(backends):
    proceed = False
    mode = 'totp'

    if ALLOW_YUBIKEY and len(sys.argv) <= 2:
        logger.critical('Enrolment mode not specified.')
    elif ALLOW_YUBIKEY:
        if sys.argv[2] not in ('totp', 'yubikey'):
            logger.critical('%s is not a valid enrollment mode' % sys.argv[2])
        else:
            mode = sys.argv[2]
            proceed = True
    else:
        proceed = True

    if not proceed:
        print('Please specify whether you are enrolling a yubikey or a TOTP phone app')
        print('Examples:')
        print('    %s enroll yubikey' % GL_2FA_COMMAND)
        print('    %s enroll totp' % GL_2FA_COMMAND)
        print_help_link()
        sys.exit(1)

    logger.info('%s enrollment mode selected' % mode)

    user = os.environ['GL_USER']

    try:
        try:
            backends.secret_backend.get_user_secret(user)
        except totpcgi.UserSecretError:
            pass

        logger.critical('User %s already enrolled' % user)
        print('Looks like you are already enrolled. If you want to re-issue your token,')
        print('you will first need to remove your currently active one.')
        print('')
        print('If you have access to your current device or 8-digit scratch codes, run:')
        print('    unenroll [token]')
        print_help_link()
        sys.exit(1)

    except totpcgi.UserNotFound:
        pass

    generate_user_token(backends, mode)


def unenroll(backends):
    token = sys.argv[2]
    user = os.environ['GL_USER']
    remote_ip = os.environ['SSH_CONNECTION'].split()[0]

    ga = totpcgi.GoogleAuthenticator(backends)

    try:
        status = ga.verify_user_token(user, token)
    except Exception, ex:
        if ALLOW_BYPASS_OVERRIDE and token == 'override':
            status = "%s uses 'override'. It's super effective!" % user
            syslog.syslog(
                syslog.LOG_NOTICE, 'OVERRIDE USED: user=%s, host=%s'
            )
        else:
            logger.critical('Failed to validate token.')
            print('If using a phone app, please wait for token to change before trying again.')
            syslog.syslog(
                syslog.LOG_NOTICE,
                'Failure: user=%s, host=%s, message=%s' % (user, remote_ip, str(ex))
            )
            print_help_link()
            sys.exit(1)

    syslog.syslog(
        syslog.LOG_NOTICE,
        'Success: user=%s, host=%s, message=%s' % (user, remote_ip, status)
    )
    logger.info(status)

    # Okay, deleting
    logger.info('Removing the secrets file.')
    backends.secret_backend.delete_user_secret(user)
    # purge all old state, as it's now obsolete
    logger.info('Cleaning up state files.')
    backends.state_backend.delete_user_state(user)
    logger.info('Expiring all validations.')
    inval(expire_all=True)

    logger.info('You have been successfully unenrolled.')


def val(backends, hours=24, authorize_ip=None, session=False):
    if len(sys.argv) <= 2:
        logger.critical('Missing tokencode.')
        print('You need to pass the token code as the last argument. E.g.:')
        print('    %s %s [token]' % (GL_2FA_COMMAND, sys.argv[1]))
        print_help_link()
        sys.exit(1)

    token = sys.argv[2]
    user = os.environ['GL_USER']
    remote_ip = os.environ['SSH_CONNECTION'].split()[0]

    ga = totpcgi.GoogleAuthenticator(backends)

    try:
        status = ga.verify_user_token(user, token)
    except Exception, ex:
        if ALLOW_BYPASS_OVERRIDE and token == 'override':
            status = "%s uses 'override'. It's super effective!" % user
            syslog.syslog(
                syslog.LOG_NOTICE, 'OVERRIDE USED: user=%s, host=%s'
            )
        else:
            logger.critical('Failed to validate token.')
            print('If using a phone app, please wait for token to change before trying again.')
            syslog.syslog(
                syslog.LOG_NOTICE,
                'Failure: user=%s, host=%s, message=%s' % (user, remote_ip, str(ex))
            )
            print_help_link()
            sys.exit(1)

    syslog.syslog(
        syslog.LOG_NOTICE,
        'Success: user=%s, host=%s, message=%s' % (user, remote_ip, status)
    )
    logger.info(status)

    if authorize_ip is None:
        authorize_ip = remote_ip

    store_validation(authorize_ip, hours, session)


def isval():
    authorized_ips = load_authorized_ips()
    remote_ip = os.environ['SSH_CONNECTION'].split()[0]

    if is_authorized_ip(remote_ip, authorized_ips):
        return True

    return False


def list_val(active_only=True):
    valdata = load_authorized_ips()
    if active_only:
        for authorized_ip in valdata.keys():
            expires = valdata[authorized_ip]['expires']
            if is_expired(expires):
                del valdata[authorized_ip]

    if valdata:
        # anyjson doesn't let us indent
        import json
        print(json.dumps(valdata, indent=4))
        if active_only:
            print('Listed non-expired entries only. Run "list-val all" to list all.')


def inval(expire_all=False):
    valdata = load_authorized_ips()
    utc = dateutil.tz.tzutc()
    now_time = datetime.datetime.now(utc).replace(microsecond=0)
    new_exp_time = now_time - datetime.timedelta(seconds=1)

    to_expire = []

    if sys.argv[2] == 'myip':
        inval_ip = os.environ['SSH_CONNECTION'].split()[0]
    elif sys.argv[2] == 'all' and len(sys.argv) > 3 and sys.argv[3] == 'purge':
        valdata = {}
        store_authorized_ips(valdata)
        logger.info('All entries purged. You can verify with "list-val all".')
        return
    elif sys.argv[2] == 'all':
        expire_all = True
    else:
        inval_ip = sys.argv[2]

    if expire_all:
        for authorized_ip in valdata:
            exp_time = dateutil.parser.parse(valdata[authorized_ip]['expires'])

            if exp_time > now_time:
                to_expire.append(authorized_ip)

    else:
        myipaddr = netaddr.IPAddress(inval_ip)
        for authorized_ip in valdata.keys():
            if myipaddr in netaddr.IPNetwork(authorized_ip):
                to_expire.append(authorized_ip)

    if to_expire:
        for inval_ip in to_expire:
            exp_time = dateutil.parser.parse(valdata[inval_ip]['expires'])

            if exp_time > now_time:
                logger.info('Force-expired %s.' % inval_ip)
                valdata[inval_ip]['expires'] = new_exp_time.isoformat(sep=' ')
            else:
                logger.info('%s was already expired.' % inval_ip)

        store_authorized_ips(valdata)
    else:
        if not expire_all:
            logger.info('Did not find %s in the list of authorized IPs.' % inval_ip)

    list_val(active_only=True)


def main():
    global logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "[%s] " % os.environ['GL_USER'] + "%(asctime)s - %(levelname)s - %(message)s")

    # We log alongside GL_LOGFILE and follow Gitolite's log structure
    (logdir, logname) = os.path.split(os.environ['GL_LOGFILE'])
    logfile = os.path.join(logdir, '2fa-command-%s' % logname)
    ch = logging.FileHandler(logfile)
    ch.setFormatter(formatter)

    if '2FA_LOG_DEBUG' in os.environ:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    ch.setLevel(loglevel)
    logger.addHandler(ch)

    # Only CRITICAL goes to console
    ch = logging.StreamHandler()

    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

    backends = totpcgi.backends.Backends()

    # We only use file backends
    secrets_dir = os.path.join(os.environ['GL_ADMIN_BASE'], '2fa/secrets')
    state_dir = os.path.join(os.environ['GL_ADMIN_BASE'], '2fa/state')
    logger.debug('secrets_dir=%s' % secrets_dir)
    logger.debug('state_dir=%s' % state_dir)

    # Create those two dirs if they don't exist
    if not os.path.exists(secrets_dir):
        os.makedirs(secrets_dir, 0700)
        logger.info('Created %s' % secrets_dir)

    if not os.path.exists(state_dir):
        os.makedirs(state_dir, 0700)
        logger.info('Created %s' % state_dir)

    backends.secret_backend = totpcgi.backends.file.GASecretBackend(secrets_dir)
    backends.state_backend = totpcgi.backends.file.GAStateBackend(state_dir)

    if len(sys.argv) < 2:
        command = 'help'
    else:
        command = sys.argv[1]

    if command == 'enroll':
        enroll(backends)

    elif command == 'unenroll':
        if len(sys.argv) <= 2:
            logger.critical('Missing authorization token.')
            print('Please use your current token code to unenroll.')
            print('You may also use a one-time 8-digit code for the same purpose.')
            print('E.g.: %s unenroll [token]' % GL_2FA_COMMAND)
            sys.exit(1)
        unenroll(backends)

    elif command == 'val':
        val(backends)

    elif command == 'val-session':
        val(backends, hours=8, authorize_ip=None, session=True)

    elif command == 'val-for-days':
        if len(sys.argv) <= 2:
            logger.critical('Missing number of days to keep the validation.')
            sys.exit(1)
        try:
            days = int(sys.argv[2])
        except ValueError:
            logger.critical('The number of days should be an integer.')
            sys.exit(1)

        if days > 30 or days < 1:
            logger.critical('The number of days must be a number between 1 and 30.')
            sys.exit(1)

        hours = days * 24

        # shift token into 2nd position
        del sys.argv[2]
        val(backends, hours=hours)

    elif command == 'val-subnet':
        myip = os.environ['SSH_CONNECTION'].split()[0]
        if len(sys.argv) <= 2:
            logger.critical('Missing the subnet mask.')
            logger.critical('Try the following to find out your subnet mask:')
            logger.critical('    whois -h whois.cymru.com " -p %s"' % myip)
            sys.exit(1)
        netmask = sys.argv[2].lstrip('/')
        try:
            netmask = int(netmask)
        except ValueError:
            logger.critical('The subnet mask is invalid.')
            sys.exit(1)

        if netmask < MAX_CIDR_SIZE:
            logger.critical('Largest allowed subnet is /%s' % MAX_CIDR_SIZE)
            sys.exit(1)

        try:
            mynetwork = netaddr.IPNetwork('%s/%s' % (myip, netmask))
            authorize_ip = str(mynetwork.cidr)
        except netaddr.AddrFormatError:
            logger.critical('Tne subnet mask is invalid.')
            sys.exit(1)

        # Limit authorization to 8 hours
        hours = 8

        # shift token into 2nd position
        del sys.argv[2]
        val(backends, hours=hours, authorize_ip=authorize_ip)

    elif command == 'list-val':
        if not isval():
            logger.critical('This command only works from a whitelisted IP')
            print_help_link()
            sys.exit(1)

        if len(sys.argv) > 2 and sys.argv[2] == 'all':
            list_val(active_only=False)
        else:
            list_val(active_only=True)

    elif command == 'inval':
        if not isval():
            logger.critical('This command only works from a whitelisted IP')
            print_help_link()
            sys.exit(1)

        if len(sys.argv) <= 2:
            logger.critical('You need to provide an IP address to invalidate.')
            logger.critical('You may use "myip" to invalidate your current IP address.')
            logger.critical('You may also use "all" to invalidate ALL currently active IP addresses.')
            logger.critical('Use "all purge" to purge all expired validations from history.')
            sys.exit(1)
        inval()

    elif command == 'isval':
        if isval():
            print("True")
            sys.exit(0)
        print("False")
        sys.exit(1)

    elif command == 'help':
        # Print out a summary of commands
        print('Command summary:')
        print('---------------|-----------------------------------------------')
        print('enroll [mode]  | Enroll with 2-factor authentication')
        print('               | (mode=totp or yubikey)')
        print('---------------|-----------------------------------------------')
        print('val [tkn]      | Validate your current IP address for 24 hours')
        print('               | (tkn means your current 2fa code)')
        print('---------------|-----------------------------------------------')

        # When ssh session is started from systemd, it will helpfully set
        # a XDG_SESSION_ID variable that is unique per connection per system uptime
        # We can use this in conjunction with ssh's ControlMaster feature to
        # validate a single ongoing session per user per remote IP.
        if 'XDG_SESSION_ID' in os.environ:
            print('val-session    | Validate your current ssh ControlMaster session')
            print(' [tkn]         | (tkn means your current 2fa code)')
            print('---------------|-----------------------------------------------')

        print('val-for-days   | Validate your current IP address for NN days')
        print(' [NN] [tkn]    | (max=30)')
        print('---------------|-----------------------------------------------')
        print('val-subnet     | Validate a subnet instead of IP for 24 hours')
        print(' [/xx] [tkn]   | (max subnet size=/%s)' % MAX_CIDR_SIZE)
        print('---------------|-----------------------------------------------')
        print('list-val [all] | List currently validated IP addresses')
        print('               | ("all" lists expired addresses as well)')
        print('---------------|-----------------------------------------------')
        print('inval [ip]     | Force-invalidate a specific IP address')
        print('               | (can be "myip" or "all" or "all purge")')
        print('---------------|-----------------------------------------------')
        print('isval          | Checks if your current IP is valid and returns')
        print('               | "True" or "False" (also sets error code)')
        print('---------------|-----------------------------------------------')
        print('unenroll [tkn] | Unenroll from 2-factor authentication')
        print_help_link()


if __name__ == '__main__':
    if 'GL_USER' not in os.environ:
        sys.stderr.write('Please run me from gitolite hooks')
        sys.exit(1)

    if 'SSH_CONNECTION' not in os.environ:
        sys.stderr.write('This only works when accessed over SSH')
        sys.exit(1)

    main()
