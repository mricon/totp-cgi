PUPPET QUICKSTART
-----------------

This document is aimed at administrators who are already running puppet
and would like to add 2-factor authentication to their infrastructure.
The provided totpcgi puppet module will allow you to quickly setup
totpcgi and require the use of Google Authenticator tokens for obtaining
elevated privileges via sudo.

This document expects that your infrastructure runs on RHEL/CentOS 6.x
with EPEL. All required packages are already part of EPEL.

Core concepts
~~~~~~~~~~~~~
Totpcgi consists of three core components:

1. The CGI that receives token information over a
   mutually-authenticated SSL connection.
2. The PAM component (pam_url) that communicates with totpcgi.
3. The provisioning cgi that provisions Google Authenticator tokens to
   users (or admins).

The most tedious component of the above setup is mutual SSL
authentication between pam_url and the totpcgi server -- which requires
setting up a CA and provisioning certificates. However, since puppet
infrastructure already relies on mutual SSL authentication in order to
communicate between the nodes and the puppet master, we will simply
reuse those certificates and thus simplify our lives dramatically.

You will still need a certificate for the user-facing component of the
setup -- the provisioning CGI.

Using the module
~~~~~~~~~~~~~~~~
This totpcgi puppet module assumes a number of things:

1. That you're using at least puppet 2.6 or above (2.6 is currently in EPEL).
2. That you don't already define a bunch of packages and services, such
   as httpd, mod_ssl, etc. Chances are, you probably already do, so you
   will need to adjust the manifests accordingly.
3. That you don't have anything useful in /etc/httpd/conf.d/ssl.conf. We
   comment out the default VirtualHost definition in there, since
   otherwise it clashes with our provisioning config.

Chances are, you will need to modify the module before it works for you,
but you shouldn't need to completely rewrite it.

Designating a server
~~~~~~~~~~~~~~~~~~~~
It's best to dedicate a separate VM for totpcgi use. It doesn't
*require* its own VM -- any webserver-capable system will do -- but
considering that it will be one of the core pieces of your security
infrastructure, you'll want to make sure it's segregated from all other
services.

.. important::

    Before you enroll the totpcgi server with puppet, make sure puppet
    generates 2048-bit keys! Puppet versions prior to 2.7 use 1024-bit
    keys by default, which is lamentably low. If you're using
    puppet-2.6, you will need to enroll the totpcgi server with puppet
    using --keylength=2048 argument. E.g.:

    puppet agent --server=puppet.example.com --keylength=2048 [etc]

Add the module to puppet
~~~~~~~~~~~~~~~~~~~~~~~~

.. important::

    Note that the default provisioning server configuration uses
    self-signed certificates. If you are going to make this component
    user-visible, you will need to set real certificates from a real CA.
    You really don't want to condition your users to expect certificate
    warnings when they go to provision their TOTP tokens!


1. Install the module into your puppet tree.
2. Modify templates/httpd-totpcgi.conf.erb to adjust the ServerName to
   something other than totp.example.com. Adjust ServerAdmin as well.
3. Modify sources/httpd-provisioning.conf and change ServerName and
   ServerAdmin to reflect reality. Adjust the certificates as well --
   see warning note above.
4. Adjust the "url" in templates/httpd-totpcgi.conf.erb to point to the
   fqdn of your newly designated totpcgi server.
5. Adjust "totp_user_mask" in sources/provisioning.conf to reflect your
   infrastructure.
6. Add "include totpcgi::server" to the totpcgi server node.
7. Add "include totpcgi::client" to all the nodes you would like to
   enroll into 2-factor authentication.

Run puppet on the server and on the clients. Tweak the manifests until
things apply cleanly. :)

.. important::

    You will need to allow network communication with your totpcgi
    server on ports 443 (provisioning CGI) and 8443 (token-checking
    CGI). This example module does not take care of this for you!

Provision yourself a token
~~~~~~~~~~~~~~~~~~~~~~~~~~
You will need to install Google Authenticator on your mobile device.
It's available in "appstores" on most smartphones, including iOS,
Android, Blackberry, etc.

Surf to your totpcgi server on the regular https port -- that's the
provisioning interface. Your browser should present you with an
authentication window. We are using mod_authnz_external that basically
does a pam-backed pwcheck. As long as PAM on the server is able to
authenticate you as your user, you should be able to provision yourself
a token.

.. important::

    Don't log in as root, obviously.

Use the "scan barcode" option in your smartphone app to import the QR
code shown on the page. Print out the rest of the page, cut out the
scratch tokens and store for emergency system access.

Use sudo with your token
~~~~~~~~~~~~~~~~~~~~~~~~
Log in to any client that you have defined as using totpcgi::client.
Attempt "sudo -i" and you should see something like this::

    [mricon@wippet ~]$ sudo -i
    [sudo] password for mricon:
    Google Authenticator Token:
    [root@wippet ~]#

Authenticate first with your password and then with your Google
Authenticator token. If it worked, congratulations!

Troubleshooting
~~~~~~~~~~~~~~~

1. Check if your clients are able to communicate with your server -- see
   if there is a record of access in
   /var/log/httpd/totpcgi-ssl-request.log
2. If there is no record of access, check that you are able to telnet to
   port 8443 from the client to the server.
3. If you are able to telnet, test to make sure you are serving the
   correct certificates on the server-side. You can do this by
   examining the certificates reported by::

       openssl s_client -connect totp.example.com:8443

   The certificate should have a CN matching the FQDN of the server, and
   it needs to be issued by the puppet CA.
4. Check /var/log/messages for output from totpcgi.
5. Check to make sure there is no time skew on the totpcgi server. You
   should be running ntp/chrony to ensure that the time is correct on
   the server.
6. As a final measure, adjust /etc/pam.d/sudo and add "debug" to the
   pam_url.so line. **WARNING: This will dump the full POST payload into
   /var/log/secure.**::
    
     auth sufficient pam_url.so debug config=/etc/pam_url.conf

   Examine the output of /var/log/secure for any clues as to why it's
   not working.

Support
~~~~~~~
Please feel free to open an issue on https://github.com/mricon/totp-cgi/
if you are having trouble getting things working.

