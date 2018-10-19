#!/usr/bin/python -tt

import os
from distutils.core import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


VERSION = '0.7.0'
NAME = 'totpcgi'

setup(
    version=VERSION,
    url='https://github.com/mricon/totp-cgi',
    name=NAME,
    description='A centralized hotp/totp solution based on google-authenticator',
    author='Konstantin Ryabitsev',
    author_email='mricon@kernel.org',
    packages=[NAME, "%s.backends" % NAME],
    license='GPLv2+',
    long_description=read('README.rst'),
)
