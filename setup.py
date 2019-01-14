import setuptools
import sys

if sys.version_info < (3, ):
    from io import open
if sys.version_info < (3, 6, ):
    import os
    here = os.path.abspath(os.path.dirname(__file__))
    readme = os.path.join(here, 'README.rst')
else:
    import pathlib
    here = pathlib.Path().cwd()
    readme = str(here.joinpath('README.rst'))

# Get the long description from the README file
with open(readme, encoding='utf-8') as fh:
    long_description = fh.read()

install_requires = ['ply>=3.11']
if sys.version_info < (3, ):
    install_requires.append('enum34')

setuptools.setup(
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
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='malware analysis yara',
    packages=setuptools.find_packages(exclude=['docs', 'examples', 'tests']),
    install_requires=install_requires,
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
