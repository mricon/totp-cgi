#!/bin/sh -e

DIRNAME=`dirname $0`
cd $DIRNAME
USAGE="$0 [ --update ]"
if [ `id -u` != 0 ]; then
echo 'You must be root to run this script'
exit 1
fi

if [ $# -eq 1 ]; then
	if [ "$1" = "--update" ] ; then
		time=`ls -l --time-style="+%x %X" totpcgi.te | awk '{ printf "%s %s", $6, $7 }'`
		rules=`ausearch --start $time -m avc --raw -se totpcgi`
		if [ x"$rules" != "x" ] ; then
			echo "Found avc's to update policy with"
			echo -e "$rules" | audit2allow -R
			echo "Do you want these changes added to policy [y/n]?"
			read ANS
			if [ "$ANS" = "y" -o "$ANS" = "Y" ] ; then
				echo "Updating policy"
				echo -e "$rules" | audit2allow -R >> totpcgi.te
				# Fall though and rebuild policy
			else
				exit 0
			fi
		else
			echo "No new avcs found"
			exit 0
		fi
	else
		echo -e $USAGE
		exit 1
	fi
elif [ $# -ge 2 ] ; then
	echo -e $USAGE
	exit 1
fi

echo "Building and Loading Policy"
set -x
make -f /usr/share/selinux/devel/Makefile || exit
/usr/sbin/semodule -i totpcgi.pp

# Fixing the file context on /var/www/totpcgi
/sbin/restorecon -F -R -v /var/www/totpcgi
# Fixing the file context on /var/www/totpcgi-provisioning
/sbin/restorecon -F -R -v /var/www/totpcgi-provisioning
# Fixing the file context on /var/lib/totpcgi
/sbin/restorecon -F -R -v /var/lib/totpcgi
# Fixing the file context on /etc/totpcgi
/sbin/restorecon -F -R -v /etc/totpcgi
