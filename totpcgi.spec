%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

%define selinux_policyver %(%{__sed} -e 's,.*selinux-policy-\\([^/]*\\)/.*,\\1,' /usr/share/selinux/devel/policyhelp || echo 0.0.0)

%define selinux_variants minimum mls targeted

%define totpcgiuser     totpcgi
%define totpcgiprovuser totpcgiprov

%define fixfiles_dirs %{_localstatedir}/www/totpcgi %{_localstatedir}/www/totpcgi-provisioning %{_localstatedir}/lib/totpcgi %{_sysconfdir}/totpcgi

Name:       totpcgi
Version:    0.6.0
Release:    1%{?dist}
Summary:    A centralized totp solution based on google-authenticator

License:    GPLv2+
URL:        https://github.com/mricon/totp-cgi
Source0:    %{name}-%{version}.tar.gz

BuildArch:  noarch

BuildRequires: checkpolicy, selinux-policy-devel, selinux-policy-doc, hardlink, python2-devel
BuildRequires: /usr/share/selinux/devel/policyhelp

Requires:   httpd, mod_ssl
Requires:   python-totpcgi = %{version}-%{release}


%description
A CGI/FCGI application to centralize google-authenticator deployments.


%package -n python-totpcgi
Summary:    Python libraries required for totpcgi
Requires:   py-bcrypt, python-pyotp, python-crypto, python-passlib

%description -n python-totpcgi
This package includes the Python libraries required for totpcgi and
totpcgi-provisioning.


%package provisioning
Summary:    CGI for Google Authenticator provisioning using totpcgi
Requires:   python-totpcgi = %{version}-%{release}
Requires:   httpd, mod_ssl, python-qrcode

%description provisioning
This package provides the CGI for provisioning Google Authenticator tokens
used by totpcgi.


%package selinux
Summary:    SELinux policies for totpcgi
Requires:   python-%{name} = %{version}-%{release}
Requires:   selinux-policy >= %{selinux_policyver}
Requires(post):   /usr/sbin/semodule, /sbin/restorecon, /sbin/fixfiles
Requires(postun): /usr/sbin/semodule, /sbin/restorecon, /sbin/fixfiles

%description selinux
This package includes SELinux policy for totpcgi and totpcgi-provisioning.

%prep
%setup -q


%build
%{__python} setup.py build
%if 0%{?el6}
pushd selinux/el6
%else
pushd selinux
%endif
for selinuxvariant in %{selinux_variants}
do
  make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile
  mv totpcgi.pp totpcgi.pp.${selinuxvariant}
  make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile clean
done
popd


%install
rm -rf %{buildroot}
%{__python} setup.py install -O1 --skip-build --root %{buildroot}

# Install config files
mkdir -p -m 0750  %{buildroot}%{_sysconfdir}/totpcgi
mkdir -p -m 0750 \
    %{buildroot}%{_sysconfdir}/totpcgi/totp \
    %{buildroot}%{_sysconfdir}/totpcgi/templates
install -m 0640 conf/*.conf %{buildroot}%{_sysconfdir}/totpcgi/
install -m 0640 conf/templates/*.html %{buildroot}%{_sysconfdir}/totpcgi/templates/

# Create the state directory
mkdir -p -m 0770 %{buildroot}%{_localstatedir}/lib/totpcgi

# Create the CGI dirs
mkdir -p -m 0751 \
    %{buildroot}%{_localstatedir}/www/totpcgi \
    %{buildroot}%{_localstatedir}/www/totpcgi-provisioning

# Install the web files
install -m 0550 cgi/totp.cgi \
    %{buildroot}%{_localstatedir}/www/totpcgi/index.cgi
install -m 0550 cgi/provisioning.cgi \
    %{buildroot}%{_localstatedir}/www/totpcgi-provisioning/index.cgi
install -m 0644 cgi/*.css \
    %{buildroot}%{_localstatedir}/www/totpcgi-provisioning/

# Install the httpd config files
mkdir -p -m 0755 %{buildroot}%{_sysconfdir}/httpd/conf.d
install -m 0644 contrib/vhost-totpcgi.conf \
    %{buildroot}%{_sysconfdir}/httpd/conf.d/totpcgi.conf
install -m 0644 contrib/vhost-totpcgi-provisioning.conf \
    %{buildroot}%{_sysconfdir}/httpd/conf.d/totpcgi-provisioning.conf

# Install totpprov script and manpage
mkdir -p -m 0755 %{buildroot}%{_bindir}
install -m 0755 contrib/totpprov.py %{buildroot}%{_bindir}/totpprov
mkdir -p -m 0755 %{buildroot}%{_mandir}/man1
install -m 0644 contrib/totpprov.1 %{buildroot}%{_mandir}/man1/

# Install SELinux files
%if 0%{?el6}
pushd selinux/el6
%else
pushd selinux
%endif
for selinuxvariant in %{selinux_variants}
do
  install -d %{buildroot}%{_datadir}/selinux/${selinuxvariant}
  install -p -m 644 totpcgi.pp.${selinuxvariant} \
    %{buildroot}%{_datadir}/selinux/${selinuxvariant}/totpcgi.pp
done
popd
/usr/sbin/hardlink -cv %{buildroot}%{_datadir}/selinux


%pre -n python-totpcgi
# We always add both the totpcgi and totpcgi-provisioning user
/usr/sbin/useradd -c "Totpcgi user" \
    -M -s /sbin/nologin -d /var/lib/totpcgi %{totpcgiuser} 2> /dev/null || :
/usr/sbin/useradd -c "Totpcgi provisioning user" \
    -M -s /sbin/nologin -d /etc/totpcgi %{totpcgiprovuser} 2> /dev/null || :

# For some reason the labeling doesn't always happen correctly
# force it if fixfiles exists
%post
if [ -f /sbin/fixfiles ] ; then
  /sbin/fixfiles -R totpcgi restore || :
fi

# For some reason the labeling doesn't always happen correctly
# force it if fixfiles exists
%post provisioning
if [ -f /sbin/fixfiles ] ; then
  /sbin/fixfiles -R totpcgi-provisioning restore || :
fi
# make sure /var/lib/totpcgi is 0770 totpcgiprov:totpcgi
chown -R %{totpcgiprovuser}:%{totpcgiuser} %{_localstatedir}/lib/totpcgi || :
chmod 0770 %{_localstatedir}/lib/totpcgi || :
# make sure state files are accessible to provisioning
chmod 0660 %{_localstatedir}/lib/totpcgi/*.json >/dev/null 2>&1 || :


%post selinux
for selinuxvariant in %{selinux_variants}
do
  /usr/sbin/semodule -s ${selinuxvariant} -i \
    %{_datadir}/selinux/${selinuxvariant}/totpcgi.pp &> /dev/null || :
done
/sbin/fixfiles restore %{fixfiles_dirs} || :

%postun selinux
if [ $1 -eq 0 ] ; then
  for selinuxvariant in %{selinux_variants}
  do
    /usr/sbin/semodule -s ${selinuxvariant} -r totpcgi &> /dev/null || :
  done
  /sbin/fixfiles restore %{fixfiles_dirs} || :
fi


%files
%doc README.rst INSTALL.rst
%doc contrib
%doc cgi/totp.fcgi
%dir %attr(-, %{totpcgiuser}, %{totpcgiuser}) %{_localstatedir}/www/totpcgi
%attr(-, %{totpcgiuser}, %{totpcgiuser}) %{_localstatedir}/www/totpcgi/*.cgi
%config(noreplace) %attr(-, -, %{totpcgiuser}) %{_sysconfdir}/totpcgi/totpcgi.conf
%config(noreplace) %{_sysconfdir}/httpd/conf.d/totpcgi.conf
%attr(-, %{totpcgiprovuser}, %{totpcgiuser}) %{_localstatedir}/lib/totpcgi

%files -n python-totpcgi
%doc COPYING
%{python_sitelib}/*
%dir %attr(-, %{totpcgiprovuser}, %{totpcgiuser}) %{_sysconfdir}/totpcgi
%dir %attr(-, %{totpcgiprovuser}, %{totpcgiuser}) %{_sysconfdir}/totpcgi/totp
%config(noreplace) %attr(-, -, %{totpcgiprovuser}) %{_sysconfdir}/totpcgi/provisioning.conf
%{_bindir}/*
%{_mandir}/*/*

%files provisioning
%dir %attr(-, %{totpcgiprovuser}, %{totpcgiprovuser}) %{_localstatedir}/www/totpcgi-provisioning
%attr(-, %{totpcgiprovuser}, %{totpcgiprovuser}) %{_localstatedir}/www/totpcgi-provisioning/*.cgi
%config(noreplace) %{_localstatedir}/www/totpcgi-provisioning/*.css
%config(noreplace) %{_sysconfdir}/httpd/conf.d/totpcgi-provisioning.conf
%dir %attr(-, -, %{totpcgiprovuser}) %{_sysconfdir}/totpcgi/templates
%config(noreplace) %attr(-, -, %{totpcgiprovuser}) %{_sysconfdir}/totpcgi/templates/*.html

%files selinux
%defattr(-,root,root,0755)
%doc selinux/*.{fc,if,sh,te}
%{_datadir}/selinux/*/totpcgi.pp


%changelog
* Sun Nov 22 2015 Konstantin Ryabitsev <mricon@kernel.org> - 0.6.0-1
- Release 0.6.0

* Thu May 22 2014 Konstantin Ryabitsev <mricon@kernel.org> - 0.6.0-0.pre.1
- New pre 0.6

* Fri Sep 20 2013 Konstantin Ryabitsev <mricon@kernel.org> - 0.5.5-1
- New version 0.5.5 with new features

* Mon Dec 03 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.5.4-1
- Make sure provisioning pages are not cached.
- Minor documentation fixes.

* Wed Nov 28 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.5.3-2
- Minor fixes for fedora-review (RHBZ #880863)

* Tue Nov 27 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.5.3-1
- Release 0.5.3 with minor fixes.

* Mon Nov 26 2012 Andrew Grimberg <agrimberg@linuxfoundation.org> - 0.5.2-2
- Move the user adds for totpcgi & totpcgiprov to python-totpcgi package

* Mon Nov 19 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.5.2-1
- Release 0.5.2 with a fix for a potential replay attack in case the
  pincode was submitted with a typo (issue #12)

* Fri Jun 29 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.5.1-1
- Release 0.5.1 with trust_http_auth functionality.

* Wed May 30 2012 Andrew Grimberg <agrimberg@linuxfoundation.org> - 0.5.0-2
- Reorder the package dependencies slightly
- Add in post scripts for totpcgi & totpcgi-provisioning for SE labeling

* Wed May 30 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.5.0-2
- Use a manual fixfiles list, as we have more than one package

* Thu May 24 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.5.0-1
- Split into more packages: totpcgi, python-totpcgi, totpcgi-provisioning, totpcgi-selinux

* Tue May 08 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.4.0-1
- Update to 0.4.0, which adds encrypted-secret functionality.
- Require python-crypto and python-passlib

* Fri May 04 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.3.1-3
- Package SELinux using Fedora's guidelines.
- Add contrib dir in its entirety.
- Use config(noreplace).

* Tue May 01 2012 Andrew Grimberg <agrimberg@linuxfoundation.org> - 0.3.1-2
- Exceptions on bad passwords to LDAP
- Config for CA cert to use for verification
- PostgreSQL pincode & secrets backends

* Thu Apr 12 2012 Andrew Grimberg <agrimberg@linuxfoundation.org> - 0.3.0-1
- Bump version number
- Split backend system

* Wed Apr 11 2012 Andrew Grimberg <agrimberg@linuxfoundation.org> - 0.2.0-4
- Add in pincode.py script

* Mon Mar 26 2012 Andrew Grimberg <agrimberg@linuxfoundation.org> - 0.2.0-3
- Fix path perms for /var/www/totpcgi so that apache can chdir
- Reduce perms on /var/www/totpcgi/totp.cgi to bare minimum

* Fri Mar 23 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.2.0-2
- Update to better match Fedora's spec standards.

* Wed Mar 21 2012 Andrew Grimberg <agrimberg@linuxfoundation.org> - 0.2.0-1
- Initial spec file creation and packaging
