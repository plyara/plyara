from setuptools import setup
import sys

import codecs
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with codecs.open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

install_requires = ['ply>=3.11']
if sys.version_info < (3, ):
    install_requires.append('enum34')

setup(
    name='plyara',
    version='1.2.2',
    description='Parse YARA rules.',
    long_description=long_description,
    url='https://github.com/plyara/plyara',
    author='8u1a',
    license='Apache License 2.0',
    test_suite='tests.unit_tests',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='malware analysis yara',
    py_modules=['plyara'],
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'plyara=plyara:main',
        ],
    },
)
