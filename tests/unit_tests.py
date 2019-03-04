#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2014 Christian Buia
# Copyright 2019 plyara Maintainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""plyara unit tests.

This module contains various unit tests for plyara.
"""
import pathlib
import subprocess
import sys
import unittest
import json

from plyara import Plyara
from plyara.exceptions import ParseTypeError, ParseValueError
from plyara.utils import generate_logic_hash
from plyara.utils import rebuild_yara_rule
from plyara.utils import detect_imports, detect_dependencies
from plyara.utils import is_valid_rule_name

UNHANDLED_RULE_MSG = 'Unhandled Test Rule: {}'

tests = pathlib.Path('tests')
data_dir = tests.joinpath('data')


class TestUtilities(unittest.TestCase):

    def test_logic_hash_generator(self):
        with data_dir.joinpath('logic_collision_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = Plyara().parse_string(inputString)

        rule_mapping = {}

        for entry in result:
            rulename = entry['rule_name']
            setname, _ = rulename.split('_')
            rulehash = generate_logic_hash(entry)

            if setname not in rule_mapping:
                rule_mapping[setname] = [rulehash]
            else:
                rule_mapping[setname].append(rulehash)

        for setname, hashvalues in rule_mapping.items():

            if not len(set(hashvalues)) == 1:
                raise AssertionError('Collision detection failure for {}'.format(setname))

    def test_is_valid_rule_name(self):
        self.assertTrue(is_valid_rule_name('test'))
        self.assertTrue(is_valid_rule_name('test123'))
        self.assertTrue(is_valid_rule_name('test_test'))
        self.assertTrue(is_valid_rule_name('_test_'))
        self.assertTrue(is_valid_rule_name('include_test'))
        self.assertFalse(is_valid_rule_name('123test'))
        self.assertFalse(is_valid_rule_name('123 test'))
        self.assertFalse(is_valid_rule_name('test 123'))
        self.assertFalse(is_valid_rule_name('test test'))
        self.assertFalse(is_valid_rule_name('test-test'))
        self.assertFalse(is_valid_rule_name('include'))
        self.assertFalse(is_valid_rule_name('test!*@&*!&'))
        self.assertFalse(is_valid_rule_name(''))

    def test_rebuild_yara_rule(self):
        with data_dir.joinpath('rebuild_ruleset.yar').open('r', encoding='utf-8') as fh:
            inputString = fh.read()

        result = Plyara().parse_string(inputString)

        rebuilt_rules = str()
        for rule in result:
            rebuilt_rules += rebuild_yara_rule(rule)

        self.assertEqual(inputString, rebuilt_rules)

    def test_rebuild_yara_rule_metadata(self):
        test_rule = """
        rule check_meta {
            meta:
                string_value = "TEST STRING"
                string_value = "DIFFERENT TEST STRING"
                bool_value = true
                bool_value = false
                digit_value = 5
                digit_value = 10
            condition:
                true
        }
        """
        parsed = Plyara().parse_string(test_rule)
        for rule in parsed:
            unparsed = rebuild_yara_rule(rule)
            self.assertIn('string_value = "TEST STRING"', unparsed)
            self.assertIn('string_value = "DIFFERENT TEST STRING"', unparsed)
            self.assertIn('bool_value = true', unparsed)
            self.assertIn('bool_value = false', unparsed)
            self.assertIn('digit_value = 5', unparsed)
            self.assertIn('digit_value = 10', unparsed)

    def test_detect_dependencies(self):
        with data_dir.joinpath('detect_dependencies_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = Plyara().parse_string(inputString)

        self.assertEqual(detect_dependencies(result[0]), list())
        self.assertEqual(detect_dependencies(result[1]), list())
        self.assertEqual(detect_dependencies(result[2]), list())
        self.assertEqual(detect_dependencies(result[3]), ['is__osx', 'priv01', 'priv02', 'priv03', 'priv04'])
        self.assertEqual(detect_dependencies(result[4]), ['is__elf', 'priv01', 'priv02', 'priv03', 'priv04'])
        self.assertEqual(detect_dependencies(result[5]), ['is__elf', 'is__osx', 'priv01', 'priv02'])
        self.assertEqual(detect_dependencies(result[6]), ['is__elf', 'is__osx', 'priv01'])
        self.assertEqual(detect_dependencies(result[7]), ['is__elf'])
        self.assertEqual(detect_dependencies(result[8]), ['is__osx', 'is__elf'])
        self.assertEqual(detect_dependencies(result[9]), ['is__osx'])
        self.assertEqual(detect_dependencies(result[10]), ['is__elf', 'is__osx'])

    def test_detect_imports(self):
        for imp in ('androguard', 'cuckoo', 'dotnet', 'elf', 'hash', 'magic', 'math', 'pe'):
            with data_dir.joinpath('import_ruleset_{}.yar'.format(imp)).open('r') as fh:
                inputString = fh.read()
            results = Plyara().parse_string(inputString)
            for rule in results:
                self.assertEqual(detect_imports(rule), [imp])


class TestRuleParser(unittest.TestCase):

    def setUp(self):
        self.parser = Plyara()

    def test_import_pe(self):
        with data_dir.joinpath('import_ruleset_pe.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertIn('pe', rule['imports'])

    def test_import_elf(self):
        with data_dir.joinpath('import_ruleset_elf.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertIn('elf', rule['imports'])

    def test_import_cuckoo(self):
        with data_dir.joinpath('import_ruleset_cuckoo.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertIn('cuckoo', rule['imports'])

    def test_import_magic(self):
        with data_dir.joinpath('import_ruleset_magic.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertIn('magic', rule['imports'])

    def test_import_hash(self):
        with data_dir.joinpath('import_ruleset_hash.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertIn('hash', rule['imports'])

    def test_import_math(self):
        with data_dir.joinpath('import_ruleset_math.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertIn('math', rule['imports'])

    def test_import_dotnet(self):
        with data_dir.joinpath('import_ruleset_dotnet.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertIn('dotnet', rule['imports'])

    def test_import_androguard(self):
        with data_dir.joinpath('import_ruleset_androguard.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertIn('androguard', rule['imports'])

    def test_scopes(self):
        with data_dir.joinpath('scope_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == 'GlobalScope':
                self.assertIn('global', entry['scopes'])

            elif rulename == 'PrivateScope':
                self.assertIn('private', entry['scopes'])

            elif rulename == 'PrivateGlobalScope':
                self.assertIn('global', entry['scopes'])
                self.assertIn('private', entry['scopes'])
            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))

    def test_tags(self):
        with data_dir.joinpath('tag_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == 'OneTag':
                self.assertEqual(len(entry['tags']), 1)
                self.assertIn('tag1', entry['tags'])

            elif rulename == 'TwoTags':
                self.assertEqual(len(entry['tags']), 2)
                self.assertIn('tag1', entry['tags'])
                self.assertIn('tag2', entry['tags'])

            elif rulename == 'ThreeTags':
                self.assertTrue(len(entry['tags']), 3)
                self.assertIn('tag1', entry['tags'])
                self.assertIn('tag2', entry['tags'])
                self.assertIn('tag3', entry['tags'])

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))

    def test_metadata(self):
        with data_dir.joinpath('metadata_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']
            kv = entry['metadata']
            kv_list = [(k,) + (v, ) for dic in kv for k, v in dic.items()]

            if rulename == 'StringTypeMetadata':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0][0], 'string_value')
                self.assertEqual(kv_list[0][1], 'String Metadata')

            elif rulename == 'IntegerTypeMetadata':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0][0], 'integer_value')
                self.assertIs(kv_list[0][1], 100)

            elif rulename == 'BooleanTypeMetadata':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0][0], 'boolean_value')
                self.assertIs(kv_list[0][1], True)

            elif rulename == 'AllTypesMetadata':
                self.assertEqual(len(kv), 3)
                self.assertEqual(kv_list[0][0], 'string_value')
                self.assertEqual(kv_list[1][0], 'integer_value')
                self.assertEqual(kv_list[2][0], 'boolean_value')
                self.assertEqual(kv_list[0][1], 'Different String Metadata')
                self.assertIs(kv_list[1][1], 33)
                self.assertIs(kv_list[2][1], False)

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))

    def test_strings(self):
        with data_dir.joinpath('string_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']
            kv = entry['strings']

            if rulename == 'Text':
                self.assertEqual(kv, [{'name': '$text_string', 'value': 'foobar', 'type': 'text'}])

            elif rulename == 'FullwordText':
                self.assertEqual(kv, [{
                    'name': '$text_string',
                    'value': 'foobar',
                    'type': 'text',
                    'modifiers': ['fullword']}])

            elif rulename == 'CaseInsensitiveText':
                self.assertEqual(kv, [{'name': '$text_string',
                                       'value': 'foobar',
                                       'type': 'text',
                                       'modifiers': ['nocase']}])

            elif rulename == 'WideCharText':
                self.assertEqual(kv, [{'name': '$wide_string',
                                       'value': 'Borland',
                                       'type': 'text',
                                       'modifiers': ['wide']}])

            elif rulename == 'WideCharAsciiText':
                self.assertEqual(kv, [{'name': '$wide_and_ascii_string',
                                       'value': 'Borland',
                                       'type': 'text',
                                       'modifiers': ['wide', 'ascii']}])

            elif rulename == 'HexWildcard':
                self.assertEqual(kv, [{'name': '$hex_string', 'value': '{ E2 34 ?? C8 A? FB }', 'type': 'byte'}])

            elif rulename == 'HexJump':
                self.assertEqual(kv, [{'name': '$hex_string', 'value': '{ F4 23 [4-6] 62 B4 }', 'type': 'byte'}])

            elif rulename == 'HexAlternatives':
                self.assertEqual(kv, [{'name': '$hex_string', 'value': '{ F4 23 ( 62 B4 | 56 ) 45 }', 'type': 'byte'}])

            elif rulename == 'HexMultipleAlternatives':
                self.assertEqual(kv, [{'name': '$hex_string',
                                       'value': '{ F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }',
                                       'type': 'byte'}])

            elif rulename == 'RegExp':
                self.assertEqual(kv, [
                    {
                        'name': '$re1',
                        'value': '/md5: [0-9a-fA-F]{32}/',
                        'type': 'regex',
                        'modifiers': ['nocase'],
                    },
                    {
                        'name': '$re2',
                        'value': '/state: (on|off)/i',
                        'type': 'regex',
                    },
                    {
                        'name': '$re3',
                        'value': r'/\x00https?:\/\/[^\x00]{4,500}\x00\x00\x00/',
                        'type': 'regex',
                    }])

            elif rulename == 'Xor':
                self.assertEqual(kv, [{'name': '$xor_string',
                                       'value': 'This program cannot',
                                       'type': 'text',
                                       'modifiers': ['xor']}])

            elif rulename == 'WideXorAscii':
                self.assertEqual(kv, [{'name': '$xor_string',
                                       'value': 'This program cannot',
                                       'type': 'text',
                                       'modifiers': ['xor', 'wide', 'ascii']}])

            elif rulename == 'WideXor':
                self.assertEqual(kv, [{'name': '$xor_string',
                                       'value': 'This program cannot',
                                       'type': 'text',
                                       'modifiers': ['xor', 'wide']}])

            elif rulename == 'DoubleBackslash':
                self.assertEqual(kv, [{'name': '$bs', 'value': r'\"\\\\\\\"', 'type': 'text'}])

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))

    def test_conditions(self):
        with data_dir.joinpath('condition_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        # Just checking for parsing errors
        self.parser.parse_string(inputString)

    def test_include(self):
        with data_dir.joinpath('include_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = self.parser.parse_string(inputString)
        self.assertEqual(result[0]['includes'], ['string_ruleset.yar'])

    def test_include_statements(self):
        self.parser.parse_string('include "file1.yara"\ninclude "file2.yara"\ninclude "file3.yara"')
        self.assertEqual(len(self.parser.includes), 3)

    def test_rules_from_yara_project(self):
        with open('tests/data/test_rules_from_yara_project.yar', 'r') as fh:
            inputRules = fh.read()

        plyara = Plyara()
        output = plyara.parse_string(inputRules)

        self.assertEqual(len(output), 293)


class TestYaraRules(unittest.TestCase):

    _PLYARA_SCRIPT_NAME = 'command_line.py'

    def test_multiple_rules(self):
        inputString = '''
        rule FirstRule {
            meta:
                author = "Andrés Iniesta"
                date = "2015-01-01"
            strings:
                $a = "hark, a \\"string\\" here" fullword ascii
                $b = { 00 22 44 66 88 aa cc ee }
            condition:
                all of them
            }

        import "bingo"
        import "bango"
        rule SecondRule : aTag {
            meta:
                author = "Ivan Rakitić"
                date = "2015-02-01"
            strings:
                $x = "hi"
                $y = /state: (on|off)/ wide
                $z = "bye"
            condition:
                for all of them : ( # > 2 )
        }

        rule ThirdRule {condition: uint32(0) == 0xE011CFD0}
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputString)

        self.assertEqual(len(result), 3)
        kv_list = [(k,) + (v, ) for dic in result[0]['metadata'] for k, v in dic.items()]
        self.assertEqual(kv_list[0][0], 'author')
        self.assertEqual(kv_list[0][1], 'Andrés Iniesta')
        self.assertEqual(kv_list[1][0], 'date')
        self.assertEqual(kv_list[1][1], '2015-01-01')
        self.assertEqual([x['name'] for x in result[0]['strings']], ['$a', '$b'])

    def disable_test_rule_name_imports_and_scopes(self):
        inputStringNIS = r'''
        rule four {meta: i = "j" strings: $a = "b" condition: true }

        global rule five {meta: i = "j" strings: $a = "b" condition: false }

        private rule six {meta: i = "j" strings: $a = "b" condition: true }

        global private rule seven {meta: i = "j" strings: $a = "b" condition: true }

        import "lib1"
        rule eight {meta: i = "j" strings: $a = "b" condition: true }

        import "lib1"
        import "lib2"
        rule nine {meta: i = "j" strings: $a = "b" condition: true }

        import "lib2"
        private global rule ten {meta: i = "j" strings: $a = "b" condition: true }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputStringNIS)

        self.assertEqual(len(result), 7)

        for rule in result:
            rule_name = rule['rule_name']

            if rule_name == 'four':
                self.assertNotIn('scopes', rule)
                self.assertIn('imports', rule)
            if rule_name == 'five':
                self.assertIn('imports', rule)
                self.assertIn('global', rule['scopes'])
            if rule_name == 'six':
                self.assertIn('imports', rule)
                self.assertIn('private', rule['scopes'])
            if rule_name == 'seven':
                self.assertIn('imports', rule)
                self.assertTrue('private' in rule['scopes'] and 'global' in rule['scopes'])
            if rule_name == 'eight':
                self.assertIn('lib1', rule['imports'])
                self.assertNotIn('scopes', rule)
            if rule_name == 'nine':
                self.assertTrue('lib1' in rule['imports'] and 'lib2' in rule['imports'])
                self.assertNotIn('scopes', rule)
            if rule_name == 'ten':
                self.assertTrue('lib1' in rule['imports'] and 'lib2' in rule['imports'])
                self.assertTrue('global' in rule['scopes'] and 'private' in rule['scopes'])

    def test_rule_name_imports_by_instance(self):
        input1 = r'''
        rule one {meta: i = "j" strings: $a = "b" condition: true }

        '''
        input2 = r'''
        import "lib1"
        rule two {meta: i = "j" strings: $a = "b" condition: true }

        import "lib2"
        private global rule three {meta: i = "j" strings: $a = "b" condition: true }
        '''

        plyara1 = Plyara()
        result1 = plyara1.parse_string(input1)

        plyara2 = Plyara()
        result2 = plyara2.parse_string(input2)

        self.assertEqual(len(result1), 1)
        self.assertEqual(len(result2), 2)

        for rule in result1:
            rule_name = rule['rule_name']

            if rule_name == 'one':
                self.assertNotIn('scopes', rule)
                self.assertNotIn('imports', rule)

        for rule in result2:
            rule_name = rule['rule_name']

            if rule_name == 'two':
                self.assertTrue('lib1' in rule['imports'] and 'lib2' in rule['imports'])
                self.assertNotIn('scopes', rule)
            if rule_name == 'three':
                self.assertTrue('lib1' in rule['imports'] and 'lib2' in rule['imports'])
                self.assertTrue('global' in rule['scopes'] and 'private' in rule['scopes'])

    def test_rule_name(self):
        inputRule = r'''
        rule testName
        {
        meta:
        my_identifier_1 = ""
        my_identifier_2 = 24
        my_identifier_3 = true

        strings:
                $my_text_string = "text here"
                $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
                $my_text_string or $my_hex_string
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRule)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['rule_name'], 'testName')

    def test_store_raw(self):
        inputRule = r'''
        rule testName
        {
        meta:
            my_identifier_1 = ""
            my_identifier_2 = 24
            my_identifier_3 = true

        strings:
            $my_text_string = "text here"
            $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
            $my_text_string or $my_hex_string
        }

        rule testName2 {
        strings:
            $test1 = "some string"

        condition:
            $test1 or true
        }

        rule testName3 {

        condition:
            true
        }

        rule testName4 : tag1 tag2 {meta: i = "j" strings: $a = "b" condition: true }
        '''

        plyara = Plyara(store_raw_sections=True)
        result = plyara.parse_string(inputRule)

        self.assertEqual(len(result), 4)
        self.assertTrue(result[0].get('raw_meta', False))
        self.assertTrue(result[0].get('raw_strings', False))
        self.assertTrue(result[0].get('raw_condition', False))

        self.assertFalse(result[1].get('raw_meta', False))
        self.assertTrue(result[1].get('raw_strings', False))
        self.assertTrue(result[1].get('raw_condition', False))

        self.assertFalse(result[2].get('raw_meta', False))
        self.assertFalse(result[2].get('raw_strings', False))
        self.assertTrue(result[2].get('raw_condition', False))

        self.assertTrue(result[3].get('raw_meta', False))
        self.assertTrue(result[3].get('raw_strings', False))
        self.assertTrue(result[3].get('raw_condition', False))

    def test_tags(self):
        inputTags = r'''
        rule eleven: tag1 {meta: i = "j" strings: $a = "b" condition: true }

        rule twelve : tag1 tag2 {meta: i = "j" strings: $a = "b" condition: true }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputTags)

        for rule in result:
            rule_name = rule['rule_name']
            if rule_name == 'eleven':
                self.assertEqual(len(rule['tags']), 1)
                self.assertIn('tag1', rule['tags'])
            if rule_name == 'twelve':
                self.assertEqual(len(rule['tags']), 2)
                self.assertIn('tag1', rule['tags'])
                self.assertIn('tag2', rule['tags'])

    def test_empty_string(self):
        inputRules = r'''
        rule thirteen
        {
        meta:
            my_identifier_1 = ""
            my_identifier_2 = 24
            my_identifier_3 = true

        strings:
            $my_text_string = "text here"
            $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
            $my_text_string or $my_hex_string
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        for rule in result:
            rule_name = rule['rule_name']
            if rule_name == 'thirteen':
                self.assertEqual(len(rule['metadata']), 3)

    def test_bytestring(self):
        inputRules = r'''
        rule testName
        {
        strings:
            $a1 = { E2 34 A1 C8 23 FB }
            $a2 = { E2 34 A1 C8 2? FB }
            $a3 = { E2 34 A1 C8 ?? FB }
            $a4 = { E2 34 A1 [6] FB }
            $a5 = { E2 34 A1 [4-6] FB }
            $a6 = { E2 34 A1 [4 - 6] FB }
            $a7 = { E2 34 A1 [-] FB }
            $a8 = { E2 34 A1 [10-] FB }
            $a9 = { E2 23 ( 62 B4 | 56 ) 45 FB }
            $a10 = { E2 23 62 B4 56 // comment
                     45 FB }
            $a11 = { E2 23 62 B4 56 /* comment */ 45 FB }
            $a12 = {
                E2 23 62 B4 56 45 FB // comment
            }

        condition:
            any of them
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(len(result), 1)
        for rule in result:
            rule_name = rule['rule_name']
            if rule_name == 'testName':
                self.assertEqual(len(rule['strings']), 12)
                for hex_string in rule['strings']:
                    # Basic sanity check.
                    self.assertIn('E2', hex_string['value'])
                    self.assertIn('FB', hex_string['value'])
                self.assertEqual(rule['strings'][0]['value'], '{ E2 34 A1 C8 23 FB }')
                self.assertEqual(rule['strings'][4]['value'], '{ E2 34 A1 [4-6] FB }')
                self.assertEqual(rule['strings'][8]['value'], '{ E2 23 ( 62 B4 | 56 ) 45 FB }')
                long_string = '{ E2 23 62 B4 56 // comment\n                     45 FB }'
                self.assertEqual(rule['strings'][9]['value'], long_string)
                self.assertEqual(rule['strings'][10]['value'], '{ E2 23 62 B4 56 /* comment */ 45 FB }')
                long_string = '{\n                E2 23 62 B4 56 45 FB // comment\n            }'
                self.assertEqual(rule['strings'][11]['value'], long_string)

    def test_nested_bytestring(self):
        inputRules = r'''
        rule sample {
            strings:
                $ = { 4D 5A ( 90 ( 00 | 01 ) | 89 ) }
            condition:
                all of them
        }
        '''

        plyara = Plyara()
        plyara.parse_string(inputRules)

    def test_bytestring_bad_jump(self):
        inputRules = r'''
        rule testName
        {
        strings:
            $a6 = { E2 34 A1 [6 - 4] FB }

        condition:
            any of them
        }
        '''

        plyara = Plyara()
        with self.assertRaises(ParseValueError):
            plyara.parse_string(inputRules)

    def test_bytestring_bad_group(self):
        inputRules = r'''
        rule sample {
            strings:
                $ = { 4D 5A ( 90 ( 00 | 01 ) | 89 ) ) }
            condition:
                all of them
        }
        '''

        plyara = Plyara()
        with self.assertRaises(ParseValueError):
            plyara.parse_string(inputRules)

    def test_rexstring(self):
        inputRules = r'''
        rule testName
        {
        strings:
            $a1 = /abc123 \d/i
            $a2 = /abc123 \d+/i // comment
            $a3 = /abc123 \d\/ afterspace/im // comment
            $a4 = /abc123 \d\/ afterspace/im nocase // comment
            $a5 = /abc123 \d\/ afterspace/nocase // comment
            $a6 = /abc123 \d\/ afterspace/nocase// comment

            /* It should only consume the regex pattern and not text modifiers
               or comment, as those will be parsed separately. */

        condition:
            any of them
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(len(result), 1)
        for rule in result:
            rule_name = rule['rule_name']
            if rule_name == 'testName':
                self.assertEqual(len(rule['strings']), 6)
                for rex_string in rule['strings']:
                    if rex_string['name'] == '$a1':
                        self.assertEqual(rex_string['value'], '/abc123 \\d/i')
                    elif rex_string['name'] == '$a2':
                        self.assertEqual(rex_string['value'], '/abc123 \\d+/i')
                    elif rex_string['name'] == '$a3':
                        self.assertEqual(rex_string['value'], '/abc123 \\d\\/ afterspace/im')
                    elif rex_string['name'] == '$a4':
                        self.assertEqual(rex_string['value'], '/abc123 \\d\\/ afterspace/im')
                        self.assertEqual(rex_string['modifiers'], ['nocase'])
                    elif rex_string['name'] in ['$a5', '$a6']:
                        self.assertEqual(rex_string['value'], '/abc123 \\d\\/ afterspace/')
                        self.assertEqual(rex_string['modifiers'], ['nocase'])
                    else:
                        self.assertFalse('Unknown string name...')

    def test_string(self):
        inputRules = r'''
        rule testName
        {
        strings:
            $a1 = "test string"
            $a2 = "test string" // comment
            $a3 = "test string" /* comment */
            $a4 = "teststring" //comment
            $a5 = "test // string" // comm ent
            $a6 = "test /* string */ string"
            $a7 = "teststring" //comment
            $a8 = "'test"
            $a9 = "'test' string"
            $a10 = "\"test string\""
            $a11 = "test \"string\""
            $a12 = "test \"string\" test \\"
            $a13 = "test string" // "comment"
            $a14 = "test string" nocase wide // comment

        condition:
            any of them
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(len(result), 1)
        for rule in result:
            self.assertEqual(len(rule['strings']), 14)
            self.assertEqual(rule['strings'][0]['value'], 'test string')
            self.assertEqual(rule['strings'][1]['value'], 'test string')
            self.assertEqual(rule['strings'][2]['value'], 'test string')
            self.assertEqual(rule['strings'][3]['value'], 'teststring')
            self.assertEqual(rule['strings'][4]['value'], 'test // string')
            self.assertEqual(rule['strings'][5]['value'], 'test /* string */ string')
            self.assertEqual(rule['strings'][6]['value'], 'teststring')
            self.assertEqual(rule['strings'][7]['value'], "'test")
            self.assertEqual(rule['strings'][8]['value'], "'test' string")
            self.assertEqual(rule['strings'][9]['value'], '\\"test string\\"')
            self.assertEqual(rule['strings'][10]['value'], 'test \\"string\\"')
            self.assertEqual(rule['strings'][11]['value'], 'test \\"string\\" test \\\\')
            self.assertEqual(rule['strings'][12]['value'], 'test string')
            self.assertEqual(rule['strings'][13]['value'], 'test string')

    def test_plyara_script(self):
        cwd = pathlib.Path().cwd()
        script_path = cwd / 'plyara' / self._PLYARA_SCRIPT_NAME
        test_file_path = cwd / 'tests' / 'data' / 'test_file.txt'

        plyara_output = subprocess.check_output([sys.executable, str(script_path), str(test_file_path)])

        rule_list = json.loads(plyara_output.decode('utf-8'))
        self.assertEqual(len(rule_list), 4)

    def test_raw_condition_contains_all_condition_text(self):
        inputRules = r'''
        rule testName {condition: any of them}
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(result[0]['raw_condition'], 'condition: any of them')

    def test_raw_strings_contains_all_string_text(self):
        inputRules = r'''
        rule testName {strings: $a = "1" condition: true}
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(result[0]['raw_strings'], 'strings: $a = "1" ')

    def test_raw_meta_contains_all_meta_text(self):
        inputRules = r'''
        rule testName {meta: author = "Test" condition: true}
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(result[0]['raw_meta'], 'meta: author = "Test" ')

        # strings after meta
        inputRules = r'''
        rule testName {meta: author = "Test" strings: $a = "1"}
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(result[0]['raw_meta'], 'meta: author = "Test" ')

    def test_parse_file_without_rules_returns_empty_list(self):
        inputRules = str()

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(result, list())

    def test_lineno_incremented_by_newlines_in_bytestring(self):
        inputRules = r'''
        rule sample
        {
            strings:
                $ = { 00 00 00 00 00 00
                      00 00 00 00 00 00 } //line 6
            conditio: //fault
                all of them
        }
        '''

        plyara = Plyara()

        with self.assertRaises(ParseTypeError):
            try:
                plyara.parse_string(inputRules)
            except ParseTypeError as e:
                self.assertEqual(7, e.lineno)
                raise e

    def test_lineno_incremented_by_windows_newlines_in_bytestring(self):
        with open('tests/data/windows_newline_ruleset.yar', 'r') as fh:
            inputRules = fh.read()

        plyara = Plyara()

        with self.assertRaises(ParseTypeError):
            try:
                plyara.parse_string(inputRules)
            except ParseTypeError as e:
                self.assertEqual(6, e.lineno)
                raise e

    def test_anonymous_array_condition(self):
        inputRules = r'''
        rule sample
        {
            strings:
                $ = { 01 02 03 04 }
            condition:
                for all of ($) : ( @ < 0xFF )
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(result[0].get('condition_terms')[8], '@')


class TestDeprecatedMethods(unittest.TestCase):  # REMOVE SOON!!

    def test_logic_hash_generator(self):
        with data_dir.joinpath('logic_collision_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = Plyara().parse_string(inputString)

        rule_mapping = {}

        for entry in result:
            rulename = entry['rule_name']
            setname, _ = rulename.split('_')
            with self.assertWarns(DeprecationWarning):
                rulehash = Plyara.generate_logic_hash(entry)

            if setname not in rule_mapping:
                rule_mapping[setname] = [rulehash]
            else:
                rule_mapping[setname].append(rulehash)

        for setname, hashvalues in rule_mapping.items():

            if not len(set(hashvalues)) == 1:
                raise AssertionError('Collision detection failure for {}'.format(setname))

    def test_is_valid_rule_name(self):
        with self.assertWarns(DeprecationWarning):
            self.assertTrue(Plyara.is_valid_rule_name('test'))
            self.assertTrue(Plyara.is_valid_rule_name('test123'))
            self.assertTrue(Plyara.is_valid_rule_name('test_test'))
            self.assertTrue(Plyara.is_valid_rule_name('_test_'))
            self.assertTrue(Plyara.is_valid_rule_name('include_test'))
            self.assertFalse(Plyara.is_valid_rule_name('123test'))
            self.assertFalse(Plyara.is_valid_rule_name('123 test'))
            self.assertFalse(Plyara.is_valid_rule_name('test 123'))
            self.assertFalse(Plyara.is_valid_rule_name('test test'))
            self.assertFalse(Plyara.is_valid_rule_name('test-test'))
            self.assertFalse(Plyara.is_valid_rule_name('include'))
            self.assertFalse(Plyara.is_valid_rule_name('test!*@&*!&'))
            self.assertFalse(Plyara.is_valid_rule_name(''))

    def test_rebuild_yara_rule(self):
        with data_dir.joinpath('rebuild_ruleset.yar').open('r', encoding='utf-8') as fh:
            inputString = fh.read()

        result = Plyara().parse_string(inputString)

        rebuilt_rules = str()
        with self.assertWarns(DeprecationWarning):
            for rule in result:
                rebuilt_rules += Plyara.rebuild_yara_rule(rule)

        self.assertEqual(inputString, rebuilt_rules)

    def test_rebuild_yara_rule_metadata(self):
        test_rule = """
        rule check_meta {
            meta:
                string_value = "TEST STRING"
                string_value = "DIFFERENT TEST STRING"
                string_value = ""
                bool_value = true
                bool_value = false
                digit_value = 5
                digit_value = 10
            condition:
                true
        }
        """
        parsed = Plyara().parse_string(test_rule)
        for rule in parsed:
            with self.assertWarns(DeprecationWarning):
                unparsed = Plyara.rebuild_yara_rule(rule)
            self.assertIn('string_value = "TEST STRING"', unparsed)
            self.assertIn('string_value = "DIFFERENT TEST STRING"', unparsed)
            self.assertIn('string_value = ""', unparsed)
            self.assertIn('bool_value = true', unparsed)
            self.assertIn('bool_value = false', unparsed)
            self.assertIn('digit_value = 5', unparsed)
            self.assertIn('digit_value = 10', unparsed)

    def test_detect_dependencies(self):
        with data_dir.joinpath('detect_dependencies_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = Plyara().parse_string(inputString)

        with self.assertWarns(DeprecationWarning):
            self.assertEqual(Plyara.detect_dependencies(result[0]), list())
            self.assertEqual(Plyara.detect_dependencies(result[1]), list())
            self.assertEqual(Plyara.detect_dependencies(result[2]), list())
            self.assertEqual(Plyara.detect_dependencies(result[3]), ['is__osx', 'priv01', 'priv02', 'priv03', 'priv04'])
            self.assertEqual(Plyara.detect_dependencies(result[4]), ['is__elf', 'priv01', 'priv02', 'priv03', 'priv04'])
            self.assertEqual(Plyara.detect_dependencies(result[5]), ['is__elf', 'is__osx', 'priv01', 'priv02'])
            self.assertEqual(Plyara.detect_dependencies(result[6]), ['is__elf', 'is__osx', 'priv01'])
            self.assertEqual(Plyara.detect_dependencies(result[7]), ['is__elf'])
            self.assertEqual(Plyara.detect_dependencies(result[8]), ['is__osx', 'is__elf'])
            self.assertEqual(Plyara.detect_dependencies(result[9]), ['is__osx'])
            self.assertEqual(Plyara.detect_dependencies(result[10]), ['is__elf', 'is__osx'])

    def test_detect_imports(self):
        for imp in ('androguard', 'cuckoo', 'dotnet', 'elf', 'hash', 'magic', 'math', 'pe'):
            with data_dir.joinpath('import_ruleset_{}.yar'.format(imp)).open('r') as fh:
                inputString = fh.read()
            results = Plyara().parse_string(inputString)
            with self.assertWarns(DeprecationWarning):
                for rule in results:
                    self.assertEqual(Plyara.detect_imports(rule), [imp])


if __name__ == '__main__':
    unittest.main()
