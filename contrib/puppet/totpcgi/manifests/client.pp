class totpcgi::client {
  package { 'pam_url':
    ensure  => present,
  }

  package { 'sudo':
    ensure => present,
  }

  file { '/etc/pam_url.conf':
    ensure   => present,
    owner    => 'root',
    group    => 'root',
    mode     => '0644',
    content  => template('totpcgi/pam_url.conf.erb'),
    checksum => 'md5',
    require  => [
      Package['pam_url'],
    ],
  }

  file { '/etc/pam.d/sudo':
    ensure   => present,
    owner    => 'root',
    group    => 'root',
    mode     => '0644',
    source   => 'puppet:///modules/totpcgi/sudo.pam',
    checksum => 'md5',
    require  => [
      File['/etc/pam_url.conf'],
      Package['sudo'],
    ],
  }
}
