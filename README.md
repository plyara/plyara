# plyara

[![PyPi Version](http://img.shields.io/pypi/v/plyara.svg)](https://pypi.python.org/pypi/plyara)

Parse [YARA](https://virustotal.github.io/yara/) rules into a dictionary representation.

Plyara is a script and library that lexes and parses a file consisting of one more YARA rules into a python dictionary representation. The goal of this tool is to make it easier to perform bulk operations or transformations of large sets of YARA rules, such as extracting indicators, updating attributes, and analyzing a corpus. Other applications include linters and dependency checkers.

Plyara leverages the Python module [PLY](https://ply.readthedocs.io/en/latest/) for lexing YARA rules.

This is a community-maintained fork of the [original plyara](https://github.com/8u1a/plyara) by [8u1a](https://github.com/8u1a). The "plyara" trademark is used with permission.

## Installation

Plyara requires Python 3.10+.

Install with pip:

```sh
pip install plyara
```

## Usage

Use the plyara Python library in your own applications:

``` python
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
```

Or, use the included `plyara` script from the command line:

```sh
$ plyara -h
usage: plyara [-h] [--log] FILE

Parse YARA rules into a dictionary representation.

positional arguments:
  FILE        File containing YARA rules to parse.

optional arguments:
  -h, --help  show this help message and exit
  --log       Enable debug logging to the console.
```

The command-line tool will print valid JSON output when parsing rules:

```yara
rule silent_banker : banker
{
    meta:
        description = "This is just an example"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
    condition:
        $a or $b or $c
}
```

Command-line tool:

```sh
plyara example.yar
```

JSON Output:

```json
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
                "threat_level": 3
            },
            {
                "in_the_wild": true
            }
        ],
        "raw_condition": "condition:\n        $a or $b or $c\n",
        "raw_meta": "meta:\n        description = \"This is just an example\"\n        threat_level = 3\n        in_the_wild = true\n    ",
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
```

## Reusing The Parser

If you want to reuse a single instance of the parser object for efficiency when parsing large quantities of rule or rulesets, the new clear() method must be used.

``` python
rules = list()
parser = plyara.Plyara()

for file in files:
    with open(file, 'r') as fh:
        yararules = parser.parse_string(fh.read())
        rules += yararules
    parser.clear()
```

## Breaking Change: Import Effects

### Background

Imports are available to be used in a rule even if not used in a condition. Also, any module which is imported at all is used in processing all files scanned using the ruleset regardless if the import is used anywhere. Some users require that all rules affected by a particular import include that import in the dictionary output of plyara. At the same time, many users expect that a particular rule not include an import if that import is not used in the rule.

### New Parameter: Import Effects

A new class constructor parameter called `import_effects` has been added to the parser. This parameter defaults to `False` which is a breaking change. Users who wish to retain the behavior from versions before 2.2, will need to set this parameter to `True` like so:

```python
parser = plyara.Plyara(import_effects=True)
```

### Note

When reusing a `parser` for multiple rules and/or files and `import_effects` is enabled, be aware that imports are now shared across all rules - if one rule has an import, that import will be added to all rules in your parser object.

## Breaking Change: Logic Hash Versions

Logic hashes now prepend a version number as well as the algorithm used to the hash itself. This will make future changes and revisions easier for uses to track. The old behavior is accessed using the `legacy` parameter on the `utils.generate_hash()` utility function.

```python
rules = Plyara().parse_string(input_string)
rulehash = generate_hash(rules[0], legacy=True)
```

## Pre-Processing

If the output of a particular rule looks incorrect after parsing by Plyara, you may be able to mitigate the problem by using YARA-X's `fmt` command for pre-processing. If you do notice a problem that requires pre-processing, please also open an issue.

```bash
yr fmt foo.yar
```

## Contributing

- If you find a bug, or would like to see a new feature, [Pull Requests](https://github.com/plyara/plyara/pulls) and [Issues](https://github.com/plyara/plyara/issues) are always welcome.
- By submitting changes, you agree to release those changes under the terms of the [LICENSE](https://github.com/plyara/plyara/blob/master/LICENSE).
- Writing passing unit tests for your changes, while not required, is highly encouraged and appreciated.
- Please run all code contributions through each of the linters that we use for this project:
  - pycodestyle
  - pydocstyle
  - pyflakes
- For more information on these linters, please refer to the [Python Code Quality Authority](https://pycqa.org/)

## Unit Tests

```bash
python -m unittest discover
```

## Coverage

```bash
coverage run -m unittest discover
coverage report -m
```
