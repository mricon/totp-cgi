totpprov
========

--------------------------------------
Simple provisioning script for totpcgi
--------------------------------------

:Author:    konstantin@linuxfoundation.org
:Date:      2013-09-20
:Copyright: Linux Foundation and contributors
:License:   GPLv2+
:Version:   0.6
:Manual section: 1

SYNOPSIS
--------
    totpprov [-c /path/to/provisioning.conf] command username

DESCRIPTION
-----------
This is a simple command-line provisioning script for totpcgi. It uses
the backend information and default parameters data found in
provisioning.conf to operate on user records.

OPTIONS
-------
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  --hotp                generate HOTP token instead of TOTP
  -c CONFIG_FILE, --config=CONFIG_FILE
                        Path to provisioning.conf
                        (Default: /etc/totpcgi/provisioning.conf)

COMMANDS
--------
delete-user
    deletes user record
delete-user-state
    deletes any existing state information for user
delete-user-pincode
    deletes pincode entry for user
delete-user-token
    deletes the token issued to user

set-user-pincode
    sets pincode for user
encrypt-user-token
    encrypts existing token with the user's pincode
decrypt-user-token
    decrypts existing encrypted token with the user's pincode
generate-user-token
    generates a new token for user
provision-user
    provisions a new user

EXAMPLES
--------
To provision a user::

    totpprov provision-user bobafett
    totpprov --hotp provision-user bobafett

To delete a user::

    totpprov delete-user bobafett

To delete a token::

    totpprov delete-user-token bobafett

To set/change user pincode::

    totpprov set-user-pincode bobafett

To generate a new google-authenticator token for user::

    totpprov generate-user-token bobafett

