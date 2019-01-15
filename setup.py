#!/usr/bin/env python3
"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""
import pathlib
from setuptools import find_packages, setup

here = pathlib.Path().cwd()

# Get the long description from the README file
with open(here.joinpath('README.rst'), encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='plyara',
    version='2.0.0',
    description='Parse YARA rules.',
    long_description=long_description,
    url='https://github.com/plyara/plyara',
    author='plyara Maintainers',
    license='Apache License 2.0',
    test_suite='tests.unit_tests',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='malware analysis yara',
    packages=find_packages(exclude=['docs', 'examples', 'tests']),
    install_requires=['ply>=3.11'],
    entry_points={
        'console_scripts': [
            'plyara=plyara.command_line:main',
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/plyara/plyara/issues',
        'Source': 'https://github.com/plyara/plyara',
    },
)
