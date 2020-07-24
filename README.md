# Plyara
[![Build Status](https://travis-ci.com/plyara/plyara.svg?branch=prep-3.0)](https://travis-ci.com/plyara/plyara)

This is the 3.0.0 development branch of Plyara. The goal is to implement `plyara` using SLY and best practices.

It is recommended to create a virtual environment in the plyara directory for an isolated development environment.

Please use the following commands to setup that virtualenv (for macOS and Linux):

**NOTE: Development requires Python 3.7+**

```
python3 -m venv venv
source venv/bin/activate
pip install -U pip setuptools
```

To install this package in development mode, please use the following command:

```
pip install -e '.[dev]'
```

Additionally, if you wish to run the unit test suite, please use the following command:

```
python -m unittest discover
````
