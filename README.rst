plyara
======

.. image:: https://api.codacy.com/project/badge/Grade/7bd0be1749804f0a8dd3d57f69888f68
   :alt: Codacy Badge
   :target: https://app.codacy.com/gh/plyara/plyara?utm_source=github.com&utm_medium=referral&utm_content=plyara/plyara&utm_campaign=Badge_Grade_Dashboard

.. image:: https://travis-ci.org/plyara/plyara.svg?branch=master
   :target: https://travis-ci.org/plyara/plyara
   :alt: Build Status
.. image:: https://readthedocs.org/projects/plyara/badge/?version=latest
   :target: http://plyara.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status
.. image:: https://api.codacy.com/project/badge/Grade/1c234b3d1ff349fa9dea7b4048dbc115
   :target: https://www.codacy.com/app/plyara/plyara
   :alt: Code Health
.. image:: https://api.codacy.com/project/badge/Coverage/1c234b3d1ff349fa9dea7b4048dbc115
   :target: https://app.codacy.com/app/plyara/plyara
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

Plyara leverages the Python module PLY_ for lexing YARA rules.

This is a community-maintained fork of the `original plyara`_ by 8u1a_. The "plyara" trademark
is used with permission.

**NOTE:** YARA rules compatible with YARA version 3.11+ are not yet supported. Specifically the `xor()` string modifier.

Installation
------------

Plyara requires Python 3.6+.

Install with pip::

    pip3 install plyara

Usage
-----

Use the plyara Python library in your own applications:

.. code-block:: python

    >>> import plyara
    >>> parser = plyara.Plyara()
    >>> mylist = parser.parse_string('rule MyRule { strings: $a="1" \n condition: false }')
    >>>
    >>> import pprint
    >>> pprint.pprint(mylist)
    [{'condition_terms': ['false'],
      'raw_condition': 'condition: false ',
      'raw_strings': 'strings: $a="1" \n ',
      'rule_name': 'MyRule',
      'start_line': 1,
      'stop_line': 2,
      'strings': [{'name': '$a', 'type': 'text', 'value': '1'}]}]
    >>>

Or, use the included ``plyara`` script from the command line::

    $ plyara -h
    usage: plyara [-h] [--log] FILE

    Parse YARA rules into a dictionary representation.

    positional arguments:
      FILE        File containing YARA rules to parse.

    optional arguments:
      -h, --help  show this help message and exit
      --log       Enable debug logging to the console.

The command-line tool will print valid JSON output when parsing rules::

    $ cat example.yar
    rule silent_banker : banker
    {
        meta:
            description = "This is just an example"
            thread_level = 3
            in_the_wild = true
        strings:
            $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
            $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
            $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
        condition:
            $a or $b or $c
    }

    $ plyara example.yar
    [
        {
            "condition_terms": [
                "$a",
                "or",
                "$b",
                "or",
                "$c"
            ],
            "metadata": [
                {
                    "description": "This is just an example"
                },
                {
                    "thread_level": 3
                },
                {
                    "in_the_wild": true
                }
            ],
            "raw_condition": "condition:\n        $a or $b or $c\n",
            "raw_meta": "meta:\n        description = \"This is just an example\"\n        thread_level = 3\n        in_the_wild = true\n    ",
            "raw_strings": "strings:\n        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}\n        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}\n        $c = \"UVODFRYSIHLNWPEJXQZAKCBGMT\"\n    ",
            "rule_name": "silent_banker",
            "start_line": 1,
            "stop_line": 13,
            "strings": [
                {
                    "name": "$a",
                    "type": "byte",
                    "value": "{6A 40 68 00 30 00 00 6A 14 8D 91}"
                },
                {
                    "name": "$b",
                    "type": "byte",
                    "value": "{8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}"
                },
                {
                    "name": "$c",
                    "type": "text",
                    "value": "UVODFRYSIHLNWPEJXQZAKCBGMT"
                }
            ],
            "tags": [
                "banker"
            ]
        }
    ]

Migration
---------

If you used an older version of plyara, and want to migrate to this version,
there will be some changes required. Most importantly, the parser object
instantiation has changed. It was:

.. code-block:: python

    # Old style - don't do this!
    import plyara.interp as interp
    rules_list = interp.parseString(open('myfile.yar').read())

But is now:

.. code-block:: python

    # New style - do this instead!
    import plyara
    parser = plyara.Plyara()
    rules_list = parser.parse_string(open('myfile.yar').read())

The existing parsed keys have stayed the same, and new ones have been added.

When reusing a ``parser`` for multiple rules and/or files, be aware that
imports are now shared across all rules - if one rule has an import, that
import will be added to all rules in your parser object.

Contributing
------------

* If you find a bug, or would like to see a new feature, Pull Requests and
  Issues_ are always welcome.
* By submitting changes, you agree to release those changes under the terms
  of the LICENSE_.
* Writing passing unit tests for your changes, while not required, is highly
  encouraged and appreciated.
* Please run all code contributions through each of the linters that we use
  for this project: pycodestyle, pydocstyle, and pyflakes.  See the
  .travis.yml file for exact use.  For more information on these linters,
  please refer to the Python Code Quality Authority:
  http://meta.pycqa.org/en/latest/

Discussion
------------

* You may join our IRC channel on irc.freenode.net #plyara

.. _PLY: http://www.dabeaz.com/ply/
.. _YARA: http://plusvic.github.io/yara/
.. _plyara.readthedocs.io: https://plyara.readthedocs.io/en/latest/
.. _original plyara: https://github.com/8u1a/plyara
.. _8u1a: https://github.com/8u1a
.. _Issues: https://github.com/plyara/plyara/issues
.. _LICENSE: https://github.com/plyara/plyara/blob/master/LICENSE
