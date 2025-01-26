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