2-factor authentication with gitolite
-------------------------------------

Security note
~~~~~~~~~~~~~
The gitolite implementation departs a bit from some of the core concepts
of totpcgi, mainly in the sense that there is no server-client
separation, nor separation between validation and provisioning. For
simplicity of user enrollment and token management, the same code acts
both for provisioning and for validation, meaning that the security
around it is less robust than around the totpcgi/pam_url combination
(where provisioning and validation is run as two different users within
two different SELinux contexts).

However, implementing provisioning-validation separation within gitolite
would be a lot more complicated, so we chose to implement it within the
same process instead of inventing complicated and fragile ways of moving
the provisioning part into a separate instance.

This implementation is NOT insecure -- it's about as secure as the
default installation of Google Authenticator's pam module. This note is
merely to point out that it's missing extra layers of security offered
by totpcgi+pam_url.

Installing
~~~~~~~~~~
.. note::

    Totpcgi version 0.6 is required for yubikey (HOTP) support to work.
    Version 0.5.x will work if you are only supporting TOTP-based
    authentication (Google Authenticator, FreeOTP, Authy, etc), but set
    ALLOW_YUBIKEY to False in this case.

This assumes that you already have gitolite-3 installed and fully
functional. Next, install totpcgi python libraries. If you are using
RHEL6/CentOS, simply do::

    yum install python-totpcgi

Alternatively, run::

    python setup.py build
    sudo python setup.py install

Make sure the following libraries are also installed:

* python-pyotp      (required)
* python-netaddr    (required)
* python-dateutil   (required)
* python-anyjson    (required)
* python-GeoIP      (optional)
* python-cymruwhois (very optional)

Next, make sure you have enabled ``LOCAL_CODE`` in your
``.gitolite.rc``. I recommend you use your gitolite-admin to manage
local modifications, so follow the guide in part 2.3 of the `customizing
gitolite`_ document and create the "local" directory in your
gitolite-admin repository.

* copy ``command.py`` into local/commands/2fa
* copy ``vref.py`` into local/VREF/2fa

You will now need to edit both of these files to reflect your local
environment -- there should be ample comments in the code. Make sure
both files are executable (chmod 0755).

Commit to gitolite-admin and push. This should have created
.gitolite/local/ in your gitolite-3 home directory. Next, you should
edit your ``.gitolite.rc`` to add "2fa" to the list of commands.

Now you need to enable the VREF check. The benefit of VREF vs. a global
hook is that you can set 2-factor requirement per repository and even
per group, so I strongly suggest that you use the "testing" repository
for the VREF check first, in order to try things out. Set it up as
follows in your ``gitolite.conf``::

    repo testing
        RW+        = @all
        - VREF/2fa = @all

This will *require* all pushes to "testing" to come from IPs that have
been 2-factor verified for that user.

If you would like to allow people to opt-in, you may add "optin" flag to
the VREF as follows::

    repo testing
        RW+              = @all
        - VREF/2fa/optin = @all

Or mix-and-match per repo/group, e.g.::

    repo testing
        RW+              = @all
        - VREF/2fa       = @coredevs
        - VREF/2fa/optin = @all

Push gitolite admin and test it out! Once you are comfortable that
things are working, configure it for other repositories (you may use
globbing, grouping, or just use ``repo @all`` to set it up for all
repositories at once, e.g.::

    repo @all

.. _`customizing gitolite`: http://gitolite.com/gitolite/cust.html

Client behaviour
~~~~~~~~~~~~~~~~
There are no configuration required on the client-side, but the next
time someone tries to push to a 2fa-required repository, the push will
fail with the following message::

    remote: User not enrolled with 2-factor authentication.
    remote: FATAL: W VREF/2fa: testing mricon DENIED by VREF/2fa
    remote: 2-factor verification failed
    remote:
    remote: You will need to enroll with 2-factor authentication
    remote: before you can push to this repository.
    remote:
    remote: If you need more help, please see the following link:
    remote:     https://example.com
    remote:
    remote: error: hook declined to update refs/heads/master

The helpful link should hopefully direct them to some document where
clients will be instructed how to enroll.

Client enrollment
~~~~~~~~~~~~~~~~~
To enroll, clients interact with the "2fa" command. To enroll a TOTP
soft-token app, such as Google Authenticator, the clients would run::

    ssh git@example.com 2fa enroll totp

This command outputs the following::

    totp enrollment mode selected
    New token generated for user mricon

    Please open an INCOGNITO/PRIVATE MODE window in your browser
    and then paste the following URL:
    https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2Fmricon%40example.com%3Fsecret%3DIVOAKYV73YGDMGOB

    Scan the resulting QR code with your TOTP app, such as
    FreeOTP (recommended), Google Authenticator, Authy, or others.
    Please write down/print the following 8-digit scratch tokens.
    If you lose your device or temporarily have no access to it, you
    will be able to use these tokens for one-time bypass.

    Scratch tokens:
    19489805
    36196876
    06341363
    70324458
    39448548

    Now run the following command to verify that all went well
        ssh git@example.com 2fa val [token]

    If you need more help, please see the following link:
        https://example.com

To initialize a yubikey, the user would run the yubikey command::

    ssh git@example.com 2fa enroll yubikey

The output of the yubikey command is slightly different::

    yubikey enrollment mode selected
    New token generated for user mricon

    Please make sure "ykpersonalize" has been installed.
    Insert your yubikey and, as root, run the following command
    to provision the secret into slot 1 (use -2 for slot 2):
        unset HISTFILE
        ykpersonalize -1 -ooath-hotp -oappend-cr -a7fd554b1e4a711155d20e9f9615b0451152db3bb

    Please write down/print the following 8-digit scratch tokens.
    If you lose your device or temporarily have no access to it, you
    will be able to use these tokens for one-time bypass.

    Scratch tokens:
    88989251
    08286736
    73163062
    90775064
    59235228

    Now run the following command to verify that all went well
        ssh git@example.com 2fa val [yubkey button press]

    If you need more help, please see the following link:
        https://example.com

Validating IPs
~~~~~~~~~~~~~~
In both cases, the user can then verify that the command has worked by
validating their current IP::

    ssh git@example.com 2fa val 359056

The output of this command is something like::

    Valid HOTP token used
    Adding IP address 172.0.0.14 until Wed May 28 17:45:33 2014 UTC

If the user now attempts to ``git push``, it will quietly succeed until
validation for that IP address expires, at which point attempting to
push will return the following::

    remote: Validation for IP address 172.0.0.14 has expired.
    remote: FATAL: W VREF/2fa: testing mricon DENIED by VREF/2fa
    remote: 2-factor verification failed
    remote:
    remote: Please get your 2-factor authentication token and run:
    remote:     ssh git@example.com 2fa val [token]
    remote:
    remote: If you need more help, please see the following link:
    remote:     https://example.com
    remote:
    remote: error: hook declined to update refs/heads/master

Users may add a validation for a period of time longer than 24 hours by
using a "val-for-days" command instead, like so::

    $ ssh git@example.com 2fa val-for-days 30 326316
    Valid HOTP token within window size used
    Adding IP address 172.0.0.14 until Thu Jun 26 17:51:29 2014 UTC

The maximum is 30 days, after which they would need to use their
2-factor token to validate again.

Listing validations and invalidating IPs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
To list their validations, clients can run::

    $ ssh git@example.com 2fa list-val
    {
        "172.0.0.14": {
            "added": "2014-05-27 17:51:29+00:00",
            "expires": "2014-06-26 17:51:29+00:00"
        }
    }
    Listed non-expired entries only. Run "list-val all" to list all.

Using "list-val all" will show ALL validations ever, as a sort of a
history for each user.

To invalidate an IP, use the "inval" command, e.g.::

    $ ssh git@example.com 2fa inval 172.0.0.14
    Force-expired 172.0.0.14.

Users may also use "myip" to invalidate the current IP the client is
accessing from, or "all" to force-expire all active IP validations.

Unenrolling
~~~~~~~~~~~
Usually clients would need to unenroll when switching devices. If they
still have access to their current device or to the scratch-tokens, they
can unenroll entirely by themselves by using the "unenroll" command::

    $ ssh git@example.com 2fa unenroll 945543
    Valid HOTP token used
    Removing the secrets file.
    Cleaning up state files.
    Expiring all validations.
    Force-expired 172.0.0.14.
    You have been successfully unenrolled.

If they do not have access to neither the previously enrolled device nor
to the 8-digit scratch tokens, you will need to manually unenroll them.

Manually unenrolling
~~~~~~~~~~~~~~~~~~~~
* Delete .gitolite/2fa/secrets/[username].*
* Delete .gitolite/2fa/state/[username].*
* Delete .gitolite/2fa/validations/[username].*

Alternatively, issue a onetime 8-digit token and add it at the bottom of
their .gitolite/2fa/secrets/[username].totp, then pass the token to the
client via the phone or some other authenticated mechanism. This will
let them unenroll by using the standard command::

    $ ssh git@example.com 2fa unenroll [onetime 8-digit token]

Known not to work
~~~~~~~~~~~~~~~~~
Gitolite mirroring using redirected pushes has not been tested and
probably won't work.

TODO
~~~~

