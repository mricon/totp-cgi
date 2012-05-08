%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

%global selinux_policyver %(%{__sed} -e 's,.*selinux-policy-\\([^/]*\\)/.*,\\1,' /usr/share/selinux/devel/policyhelp || echo 0.0.0)

%global selinux_variants mls strict targeted

%define libname totpcgi

Name:		python-%{libname}
Version:	0.4.0
Release:	1%{?dist}
Summary:	A centralized totp solution based on google-authenticator

License:	GPLv2+
URL:		https://github.com/mricon/totp-cgi
Source0:	%{libname}-%{version}.tar.gz

BuildArch:	noarch

BuildRequires: checkpolicy, selinux-policy-devel, hardlink
BuildRequires: /usr/share/selinux/devel/policyhelp

Requires:	py-bcrypt, python-pyotp, httpd, mod_ssl
Requires:   selinux-policy >= %{selinux_policyver}

%description
A CGI/FCGI application to centralize google-authenticator deployments.


%package selinux
Summary:    SELinux policies for totpcgi
Requires:   %{name} = %{version}-%{release}
Requires(post):   /usr/sbin/semodule, /sbin/restorecon, /sbin/fixfiles
Requires(postun): /usr/sbin/semodule, /sbin/restorecon, /sbin/fixfiles

%description selinux
This package includes SELinux policy for totpcgi.


%prep
%setup -q -n %{libname}-%{version}


%build
%{__python} setup.py build
cd selinux
for selinuxvariant in %{selinux_variants}
do
  make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile
  mv totpcgi.pp totpcgi.pp.${selinuxvariant}
  make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile clean
done
cd -


#%check
#%{__python} test.py


%install
%{__rm} -rf ${RPM_BUILD_ROOT}
%{__python} setup.py install -O1 --skip-build --root ${RPM_BUILD_ROOT}
%{__mkdir} -p -m 0750 ${RPM_BUILD_ROOT}%{_sysconfdir}/%{libname}/totp
%{__install} -m 0640 %{libname}.conf ${RPM_BUILD_ROOT}%{_sysconfdir}/%{libname}/
%{__mkdir} -p -m 0700 ${RPM_BUILD_ROOT}%{_localstatedir}/lib/%{libname}
%{__mkdir} -p ${RPM_BUILD_ROOT}%{_localstatedir}/www/%{libname}
%{__install} -m 0550 totp.cgi ${RPM_BUILD_ROOT}%{_localstatedir}/www/%{libname}/
%{__mkdir} -p ${RPM_BUILD_ROOT}%{_sysconfdir}/httpd/conf.d
%{__install} -m 0644 contrib/vhost-totp-cgi.conf ${RPM_BUILD_ROOT}%{_sysconfdir}/httpd/conf.d/totp-cgi.conf

for selinuxvariant in %{selinux_variants}
do
  install -d %{buildroot}%{_datadir}/selinux/${selinuxvariant}
  install -p -m 644 selinux/totpcgi.pp.${selinuxvariant} \
    %{buildroot}%{_datadir}/selinux/${selinuxvariant}/totpcgi.pp
done
/usr/sbin/hardlink -cv %{buildroot}%{_datadir}/selinux


%pre
# Add the "totpcgi" user
/usr/sbin/useradd -c "Totpcgi user" \
	-M -s /sbin/nologin -d /var/lib/%{libname} %{libname} 2> /dev/null || :


%post selinux
for selinuxvariant in %{selinux_variants}
do
  /usr/sbin/semodule -s ${selinuxvariant} -i \
    %{_datadir}/selinux/${selinuxvariant}/totpcgi.pp &> /dev/null || :
done
/sbin/fixfiles -R totpcgi restore || :

%postun selinux
if [ $1 -eq 0 ] ; then
  for selinuxvariant in %{selinux_variants}
  do
    /usr/sbin/semodule -s ${selinuxvariant} -r totpcgi &> /dev/null || :
  done
  /sbin/fixfiles -R totpcgi restore || :
fi


%files
%doc README.rst COPYING INSTALL.rst
%doc contrib
%doc totp.fcgi
%{python_sitelib}/*
%attr(0750, root, %{libname}) %{_sysconfdir}/%{libname}
%attr(-, %{libname}, %{libname}) %{_localstatedir}/lib/%{libname}
%attr(0551, %{libname}, %{libname}) %{_localstatedir}/www/%{libname}
%attr(0550, %{libname}, %{libname}) %{_localstatedir}/www/%{libname}/totp.cgi
%config(noreplace) %attr(0440, -, %{libname}) %{_sysconfdir}/%{libname}/%{libname}.conf
%config(noreplace) %attr(0644, -, -) %{_sysconfdir}/httpd/conf.d/totp-cgi.conf

%files selinux
%defattr(-,root,root,0755)
%doc selinux/*.{fc,if,sh,te}
%{_datadir}/selinux/*/totpcgi.pp


%changelog
* Tue May 08 2012 Konstantin Ryabitsev <mricon@kernel.org> - 0.4.0-1
- Update to 0.4.0, which adds encrypted-secret functionality.

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
