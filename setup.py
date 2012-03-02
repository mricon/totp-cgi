#!/usr/bin/python -tt

from distutils.core import setup

setup(
    version='0.2.0',
    url='https://github.com/mricon/totp-cgi',
    name='totpcgi',
    description='A centralized totp solution based on google-authenticator',
    author='Konstantin Ryabitsev',
    author_email='mricon@kernel.org',
    packages=['totpcgi'],
    license='GPLv2+',
)
