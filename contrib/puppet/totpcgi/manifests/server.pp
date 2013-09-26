class totpcgi::server {

  package { 'httpd':
    ensure => present,
  }

  service { 'httpd':
    ensure     => running,
    enable     => true,
    hasrestart => true,
    hasstatus  => true,
    require    => Package['httpd'],
  }

  package { 'mod_ssl':
    ensure => present,
  }

  package { 'mod_authnz_external':
    ensure  => present,
    require => Package['mod_ssl'],
  }

  selboolean { 'allow_httpd_mod_auth_pam':
    value      => 'on',
    persistent => true,
    require    => Package['mod_authnz_external'],
  }

  package { ['totpcgi', 'totpcgi-selinux', 'totpcgi-provisioning']:
    ensure  => present,
    require => [
      Package['mod_ssl'],
    ],
  }

  file { '/etc/totpcgi/totpcgi.conf':
    ensure   => present,
    owner    => 'root',
    group    => 'totpcgi',
    mode     => '0640',
    seltype  => 'httpd_totpcgi_etc_t',
    source   => 'puppet:///modules/totpcgi/totpcgi.conf',
    checksum => 'md5',
    require  => [
      Package['totpcgi-selinux'],
    ],
  }

  file { '/etc/totpcgi/provisioning.conf':
    ensure   => present,
    owner    => 'root',
    group    => 'totpcgiprov',
    mode     => '0640',
    seltype  => 'httpd_totpcgi_etc_t',
    source   => 'puppet:///modules/totpcgi/provisioning.conf',
    checksum => 'md5',
    require  => [
      Package['totpcgi-selinux'],
    ],
  }

  file { '/etc/httpd/conf.d/totpcgi.conf':
    ensure   => present,
    owner    => 'root',
    group    => 'root',
    mode     => '0644',
    content  => template('totpcgi/httpd-totpcgi.conf.erb'),
    checksum => 'md5',
    require  => [
      Package['totpcgi'],
    ],
    notify   => Service['httpd'],
  }

  file { '/etc/httpd/conf.d/ssl.conf':
    ensure   => present,
    owner    => 'root',
    group    => 'root',
    mode     => '0644',
    source   => 'puppet:///modules/totpcgi/httpd-ssl.conf',
    checksum => 'md5',
    require  => [
      Package['mod_ssl'],
    ],
    notify   => Service['httpd'],
  }

  file { '/etc/httpd/conf.d/totpcgi-provisioning.conf':
    ensure   => present,
    owner    => 'root',
    group    => 'root',
    mode     => '0644',
    source   => 'puppet:///modules/totpcgi/httpd-provisioning.conf',
    checksum => 'md5',
    require  => [
      Package['totpcgi-provisioning'],
      Package['mod_authnz_external'],
    ],
    notify   => Service['httpd'],
  }
}
