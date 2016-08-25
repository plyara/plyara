#! /usr/bin/env python2.7

from distutils.core import setup

setup(
    name             =   "Plyara",
    packages         =   ['plyara'],
    version          =   '0.1.0',
    description      =   'Parse Yara Rules',
    install_requires =   ['ply>=3.7']
)
