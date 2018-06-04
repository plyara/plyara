plyara
======

.. image:: https://travis-ci.org/plyara/plyara-fork.svg?branch=master
   :target: https://travis-ci.org/plyara/plyara-fork
   :alt: Build Status
.. image:: https://readthedocs.org/projects/plyara/badge/?version=latest
   :target: http://plyara.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status
.. image:: https://api.codacy.com/project/badge/Grade/1c234b3d1ff349fa9dea7b4048dbc115
   :target: https://www.codacy.com/app/plyara/plyara-fork
   :alt: Code Health
.. image:: https://api.codacy.com/project/badge/Coverage/1c234b3d1ff349fa9dea7b4048dbc115
   :target: https://app.codacy.com/app/plyara/plyara-fork
   :alt: Test Coverage
.. image:: http://img.shields.io/pypi/v/plyara.svg
   :target: https://pypi.python.org/pypi/plyara
   :alt: PyPi Version

Parse YARA_ rules into a dictionary representation.

Plyara is a script and library that lexes and parses a file consisting of one more YARA rules
into a python dictionary representation. The goal of this tool is to make it easier to perform
bulk operations or transformations of large sets of YARA rules, such as extracting indicators,
updating attributes, and analyzing a corpus. Other applications include linters and dependency
checkers.

Plyara leverages the Python module Ply_ for lexing YARA rules.

Installation
------------

Install with pip::

    pip install plyara

Usage
-----

Use the included ``plyara`` script from the command line::

    $ plyara -h
    usage: plyara.py [-h] [--log] FILE

    Parse YARA rules into a dictionary representation.

    positional arguments:
      FILE        File containing YARA rules to parse.

    optional arguments:
      -h, --help  show this help message and exit
      --log       Enable debug logging to the console.

Or, use the plyara Python library in your own applications::

    >>> import plyara
    >>> parser = plyara.Plyara()
    >>> mylist = parser.parse_string('rule MyRule { strings: $a="1" \n condition: false }')
    >>>
    >>> import pprint
    >>> pprint.pprint(mylist)
    [{'condition_terms': ['false'],
      'raw_condition': 'condition: false',
      'raw_strings': 'strings: $a="1" \n',
      'rule_name': 'MyRule',
      'start_line': 1,
      'stop_line': 2,
      'strings': [{'name': '$a', 'value': '"1"'}]}]
    >>>

For complete documentation, visit plyara.readthedocs.io_.

.. _Ply: http://www.dabeaz.com/ply/
.. _YARA: http://plusvic.github.io/yara/
.. _plyara.readthedocs.io: https://plyara.readthedocs.io/en/latest/
