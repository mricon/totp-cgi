#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#  Copyright 2002  The FreeRADIUS server project
#  Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
#

#
# This script has been modified from the
# example code for use with rlm_perl
#
# You can use every module that comes with your perl distribution!
#
# If you are using DBI and do some queries to DB, please be sure to
# use the CLONE function to initialize the DBI connection to DB.
#

use strict;

# This is very important ! Without this script will not get the filled hashes from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK);

use IO::Socket::SSL;
use Net::SSLeay;
use Net::LDAP;
use Net::LDAP::Util qw(escape_filter_value);
use LWP::UserAgent;
use YAML::Syck;

$YAML::Syck::ImplicitTyping = 1;

# Load in our configuration options
my $config = LoadFile('/etc/raddb/totpcgi-handler.yaml');

# We only read some of the radius attributes. If you need more
# update this array and %attrib_map
my @attrs = [
	'uid',			# to verify we're getting info on the correct user
	'dialupAccess',		# required - string value set to TRUE is required for access
	'radiusGroupName',	# optional - RADIUS Group-Name to apply to access
	'radiusFilterId',	# optional - RADIUS Filter name to apply to access
	'radiusFramedIPAddress',# optional - static IP assignment
	'radiusFramedIPNetmask',# optional - netmask for static IP assignment
	'radiusIdleTimeout',	# optional - idle timeout in seconds
	'radiusServiceType',	# optional - access control parameter (for Cisco CLI access)
	'radiusSessionTimeout'	# optional - session timeout in seconds
	];

# Map the LDAP attributes to RADIUS AV pair attributes
# We only support some of the options, if you need to map more
# check the ldap.attrmap file and add in more
# 
# NOTE: Cisco docs say to use Group-Name but that doesn't work correctly
# for some reason, Class is a IETF mapped attribute and does work
my %attrib_map = (
		'radiusGroupName'	=> 'Class',
		'radiusFramedIPAddress'	=> 'Framed-IP-Address',
		'radiusFramedIPNetmask'	=> 'Framed-IP-Netmask',
		'radiusFilterId'	=> 'Filter-Id',
		'radiusIdleTimeout'	=> 'Idle-Timeout',
		'radiusServiceType'	=> 'Service-Type',
		'radiusSessionTimeout'	=> 'Session-Timeout',
	);

# Configure our SSL sockets to use the configured certificate info
IO::Socket::SSL::set_ctx_defaults(
	verify_mode => Net::SSLeay->VERIFY_PEER(),
	ca_file     => $$config{'ca_file'},
	key_file    => $$config{'key_file'},
	cert_file   => $$config{'cert_file'},
	use_cert    => 1,
);

# Hash which holds the original requiest from radius
#my %RAD_REQUEST;
# In this hash you add values that will be returned to NAS.
#my %RAD_REPLY;
# This is for check items
#my %RAD_CHECK;

#
# This the remapping of return values
#
	use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
	use constant	RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
	use constant	RLM_MODULE_OK=>        2;#  /* the module is OK, continue */
	use constant	RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
	use constant	RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
	use constant	RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
	use constant	RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
	use constant	RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
	use constant	RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
	use constant	RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */

# Function to handle authorize
sub authorize {
	# For debugging purposes only
#	&log_request_attributes;

	# Here's where your authorization code comes
	# You can call another function from here:
#	&test_call;

	return RLM_MODULE_OK;
}

# Function to handle authenticate
sub authenticate {
	# For debugging purposes only
	#&log_request_attributes;

	# default to rejecting (with no message)
	my $retcode = RLM_MODULE_REJECT;

	# New web object to post to totp-cgi
	my $ua = LWP::UserAgent->new;
	my %form = (
		'mode'  => 'PAM_SM_AUTH',
		'user'  => $RAD_REQUEST{'User-Name'},
		'token' => $RAD_REQUEST{'User-Password'},
	);

	my $response = $ua->post($$config{'totpurl'}, \%form);

	if ($response->is_success) {
		# successfully authenticated with password & token
		# check for VPN information
		# keep our timeout short so that we failover fairly fast
		# we need to do this to make sure our RADIUS checks
		# happen in a fast enough manner
		my $ldap = Net::LDAP->new($$config{'ldaphosts'}, timeout => 10);
		if ($ldap)
		{
			my $mesg = $ldap->bind($$config{'binddn'}, password => $$config{'bindpwd'});

			# The search filter should have a USERNAME string in it for replacement
			# with the uid we're searching for
			my $my_filter = $$config{'search'};
			my $escaped_user = escape_filter_value($RAD_REQUEST{'User-Name'});
			$my_filter =~ s/USERNAME/$escaped_user/;

			$mesg = $ldap->search(
				base	=> $$config{'searchbase'},
				filter	=> $my_filter,
				scope	=> $$config{'searchscope'},
				attrs	=> @attrs
				);

			# We check $mesg->entry(0) only as we should only be getting
			# back one entry
			if ($mesg->count() && $mesg->entry(0)->attributes() &&
				($mesg->entry(0)->get_value('uid') == $RAD_REQUEST{'User-Name'}))
			{
				my $entry = $mesg->entry(0);

				if ($entry->exists('dialupAccess') && (uc($entry->get_value('dialupAccess')) eq 'TRUE'))
				{
					foreach my $attrib ($entry->attributes())
					{
						if ($attrib_map{$attrib})
						{
							$RAD_REPLY{$attrib_map{$attrib}} = $entry->get_value($attrib);
						}
					}
					$retcode = RLM_MODULE_OK;
				}
				else
				{
					$RAD_REPLY{'Reply-Message'} = 'Denied access by rlm_perl: dialupAccess not TRUE';
				}
			}
			else
			{
				$RAD_REPLY{'Reply-Message'} = 'Denied access by rlm_perl: no LDAP RADIUS attributes found';
			}
			# clean-up our connection
			$ldap->unbind;
		}
		else
		{
			# Our LDAP servers have gone away, we can't
			# get informationon the user, reject them
			$RAD_REPLY{'Reply-Message'} = 'Denied access by rlm_perl: LDAP server(s) have gone away';
		}
	} else {
		$RAD_REPLY{'Reply-Message'} = 'Denied access by rlm_perl authenticate function';
	}

	# Make sure a REJECT has some sort of message
	if ( $retcode == RLM_MODULE_REJECT && !$RAD_REPLY{'Reply-Message'} )
	{
		$RAD_REPLY{'Reply-Message'} = 'Denied access by rlm_perl: unknown error';
	}

	return $retcode;
}

# Function to handle preacct
sub preacct {
	return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {
	# For debugging purposes only
#	&log_request_attributes;

	# You can call another subroutine from here
#	&test_call;

	return RLM_MODULE_OK;
}

# Function to handle checksimul
sub checksimul {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {
	# For debugging purposes only
#	&log_request_attributes;

	# Loads some external perl and evaluate it
#	my ($filename,$a,$b,$c,$d) = @_;
#	&radiusd::radlog(1, "From xlat $filename ");
#	&radiusd::radlog(1,"From xlat $a $b $c $d ");
#	local *FH;
#	open FH, $filename or die "open '$filename' $!";
#	local($/) = undef;
#	my $sub = <FH>;
#	close FH;
#	my $eval = qq{ sub handler{ $sub;} };
#	eval $eval;
#	eval {main->handler;};
}

# Function to handle detach
sub detach {
	# For debugging purposes only
#	&log_request_attributes;

	# Do some logging.
	&radiusd::radlog(0,"rlm_perl::Detaching. Reloading. Done.");
}

#
# Some functions that can be called from other functions
#

sub test_call {
	# Some code goes here
}

sub log_request_attributes {
	# This shouldn't be done in production environments!
	# This is only meant for debugging!
	for (keys %RAD_REQUEST) {
		&radiusd::radlog(1, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}");
	}
}

