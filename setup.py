from setuptools import setup, find_packages
import sys

from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

install_requires = ['ply']
if sys.version_info < (3, ):
    install_requires.append('enum34')

setup(
    name='plyara',

    version='1.1.0',

    description='Parse Yara Rules',
    long_description=long_description,

    url='https://github.com/8u1a/plyara',

    author='8u1a',

    license='Apache License 2.0',

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

    packages=find_packages(exclude=['examples', 'tests']),

    install_requires=install_requires,

    entry_points={
        'console_scripts': [
            'plyara=plyara.plyara:main',
        ],
    },
)
