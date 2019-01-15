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
import ast
import pathlib
import subprocess
import sys
import unittest

from plyara.core import Plyara
from plyara.exceptions import ParseTypeError, ParseValueError
from plyara.utils import *

UNHANDLED_RULE_MSG = 'Unhandled Test Rule: {}'

class TestStaticMethods(unittest.TestCase):

    def test_logic_hash_generator(self):
        with open('tests/data/logic_collision_ruleset.yar', 'r') as f:
            inputString = f.read()

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
        with open('tests/data/rebuild_ruleset.yar', 'r', encoding='utf-8') as f:
            inputString = f.read()

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
           self.assertTrue('string_value = "TEST STRING"' in unparsed)
           self.assertTrue('string_value = "DIFFERENT TEST STRING"' in unparsed)
           self.assertTrue('bool_value = true' in unparsed)
           self.assertTrue('bool_value = false' in unparsed)
           self.assertTrue('digit_value = 5' in unparsed)
           self.assertTrue('digit_value = 10' in unparsed)

    def test_detect_dependencies(self):
        with open('tests/data/detect_dependencies_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = Plyara().parse_string(inputString)

        self.assertEqual(detect_dependencies(result[0]), [])
        self.assertEqual(detect_dependencies(result[1]), [])
        self.assertEqual(detect_dependencies(result[2]), [])
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
            with open('tests/data/import_ruleset_{}.yar'.format(imp), 'r') as f:
                inputString = f.read()
            results = Plyara().parse_string(inputString)
            for rule in results:
                self.assertEqual(detect_imports(rule), [imp])


class TestRuleParser(unittest.TestCase):

    def setUp(self):
        self.parser = Plyara()

    def test_import_pe(self):
        with open('tests/data/import_ruleset_pe.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('pe' in rule['imports'])

    def test_import_elf(self):
        with open('tests/data/import_ruleset_elf.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('elf' in rule['imports'])

    def test_import_cuckoo(self):
        with open('tests/data/import_ruleset_cuckoo.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('cuckoo' in rule['imports'])

    def test_import_magic(self):
        with open('tests/data/import_ruleset_magic.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('magic' in rule['imports'])

    def test_import_hash(self):
        with open('tests/data/import_ruleset_hash.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('hash' in rule['imports'])

    def test_import_math(self):
        with open('tests/data/import_ruleset_math.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('math' in rule['imports'])

    def test_import_dotnet(self):
        with open('tests/data/import_ruleset_dotnet.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('dotnet' in rule['imports'])

    def test_import_androguard(self):
        with open('tests/data/import_ruleset_androguard.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('androguard' in rule['imports'])

    def test_scopes(self):
        with open('tests/data/scope_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == 'GlobalScope':
                self.assertTrue('global' in entry['scopes'])

            elif rulename == 'PrivateScope':
                self.assertTrue('private' in entry['scopes'])

            elif rulename == 'PrivateGlobalScope':
                self.assertTrue('global' in entry['scopes'] and
                                'private' in entry['scopes'])
            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))

    def test_tags(self):
        with open('tests/data/tag_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == 'OneTag':
                self.assertTrue(len(entry['tags']) == 1 and
                                'tag1' in entry['tags'])

            elif rulename == 'TwoTags':
                self.assertTrue(len(entry['tags']) == 2 and
                                'tag1' in entry['tags'] and
                                'tag2' in entry['tags'])

            elif rulename == 'ThreeTags':
                self.assertTrue(len(entry['tags']) == 3 and
                                'tag1' in entry['tags'] and
                                'tag2' in entry['tags'] and
                                'tag3' in entry['tags'])

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))

    def test_metadata(self):
        with open('tests/data/metadata_ruleset.yar', 'r') as f:
            inputString = f.read()

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
        with open('tests/data/string_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']
            kv = entry['strings']
            kv_list = [tuple(x.values()) for x in kv]

            if rulename == 'Text':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$text_string', 'foobar', 'text', ))

            elif rulename == 'FullwordText':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$text_string', 'foobar', 'text', ['fullword'], ))

            elif rulename == 'CaseInsensitiveText':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$text_string', 'foobar', 'text', ['nocase'], ))

            elif rulename == 'WideCharText':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$wide_string', 'Borland', 'text', ['wide'], ))

            elif rulename == 'WideCharAsciiText':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$wide_and_ascii_string', 'Borland', 'text', ['wide', 'ascii'], ))

            elif rulename == 'HexWildcard':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$hex_string', '{ E2 34 ?? C8 A? FB }', 'byte', ))

            elif rulename == 'HexJump':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$hex_string', '{ F4 23 [4-6] 62 B4 }', 'byte', ))

            elif rulename == 'HexAlternatives':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$hex_string', '{ F4 23 ( 62 B4 | 56 ) 45 }', 'byte', ))

            elif rulename == 'HexMultipleAlternatives':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$hex_string', '{ F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }', 'byte', ))

            elif rulename == 'RegExp':
                self.assertEqual(len(kv), 3)
                self.assertEqual(kv_list[0][0], '$re1')
                self.assertEqual(kv_list[0][1], '/md5: [0-9a-fA-F]{32}/')
                self.assertEqual(kv_list[0][2], 'regex')
                self.assertEqual(kv_list[1][0], '$re2')
                self.assertEqual(kv_list[1][1], '/state: (on|off)/i')
                self.assertEqual(kv_list[1][2], 'regex')
                self.assertEqual(kv_list[2][0], '$re3')
                self.assertEqual(kv_list[2][1], r'/\x00https?:\/\/[^\x00]{4,500}\x00\x00\x00/')
                self.assertEqual(kv_list[2][2], 'regex')

            elif rulename == 'Xor':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$xor_string', 'This program cannot', 'text', ['xor'], ))

            elif rulename == 'WideXorAscii':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$xor_string', 'This program cannot', 'text', ['xor', 'wide', 'ascii'], ))

            elif rulename == 'WideXor':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0], ('$xor_string', 'This program cannot', 'text', ['xor', 'wide'], ))

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))

    def test_conditions(self):
        with open('tests/data/condition_ruleset.yar', 'r') as f:
            inputString = f.read()

        # Just checking for parsing errors
        self.parser.parse_string(inputString)

    def test_include(self):
        with open('tests/data/include_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)
        self.assertEqual(result[0]['includes'], ['string_ruleset.yar'])

    def test_include_statements(self):
        self.parser.parse_string('include "file1.yara"\ninclude "file2.yara"\ninclude "file3.yara"')
        self.assertEqual(len(self.parser.includes), 3)


class TestYaraRules(unittest.TestCase):

    _PLYARA_SCRIPT_NAME = 'command_line.py'

    def test_multiple_rules(self):
        inputString = u'''
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
        self.assertEqual(kv_list[0][1], u'Andrés Iniesta')
        self.assertEqual(kv_list[1][0], 'date')
        self.assertEqual(kv_list[1][1], '2015-01-01')
        self.assertTrue([x['name'] for x in result[0]['strings']] == ['$a', '$b'])

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
                self.assertTrue('scopes' not in rule)
                self.assertTrue('imports' in rule)
            if rule_name == 'five':
                self.assertTrue('imports' in rule)
                self.assertTrue('global' in rule['scopes'])
            if rule_name == 'six':
                self.assertTrue('imports' in rule)
                self.assertTrue('private' in rule['scopes'])
            if rule_name == 'seven':
                self.assertTrue('imports' in rule)
                self.assertTrue('private' in rule['scopes'] and 'global' in rule['scopes'])
            if rule_name == 'eight':
                self.assertTrue('lib1' in rule['imports'])
                self.assertTrue('scopes' not in rule)
            if rule_name == 'nine':
                self.assertTrue('lib1' in rule['imports'] and 'lib2' in rule['imports'])
                self.assertTrue('scopes' not in rule)
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
                self.assertTrue('scopes' not in rule)
                self.assertTrue('imports' not in rule)

        for rule in result2:
            rule_name = rule['rule_name']

            if rule_name == 'two':
                self.assertTrue('lib1' in rule['imports'] and 'lib2' in rule['imports'])
                self.assertTrue('scopes' not in rule)
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

        self.assertTrue(len(result) == 1)
        self.assertTrue(result[0]['rule_name'] == 'testName')

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

        self.assertTrue(len(result) == 4)
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
                self.assertTrue(len(rule['tags']) == 1 and 'tag1' in rule['tags'])
            if rule_name == 'twelve':
                self.assertTrue(len(rule['tags']) == 2 and
                        'tag1' in rule['tags'] and 'tag2' in rule['tags'])

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
                self.assertTrue(len(rule['metadata']) == 3)

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
                self.assertEqual(rule['strings'][9]['value'], '{ E2 23 62 B4 56 // comment\n                     45 FB }')
                self.assertEqual(rule['strings'][10]['value'], '{ E2 23 62 B4 56 /* comment */ 45 FB }')
                self.assertEqual(rule['strings'][11]['value'], '{\n                E2 23 62 B4 56 45 FB // comment\n            }')

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
        result = plyara.parse_string(inputRules)

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
            result = plyara.parse_string(inputRules)

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
            result = plyara.parse_string(inputRules)

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

        process = subprocess.run([sys.executable, script_path, test_file_path], capture_output=True)

        rule_list = ast.literal_eval(process.stdout.decode('utf-8'))
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
        inputRules = ''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(result, [])

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
                result = plyara.parse_string(inputRules)
            except ParseTypeError as e:
                self.assertEqual(7, e.lineno)
                raise e

    def test_lineno_incremented_by_windows_newlines_in_bytestring(self):
        with open('tests/data/windows_newline_ruleset.yar', 'r') as f:
            inputRules = f.read()

        plyara = Plyara()

        with self.assertRaises(ParseTypeError):
            try:
                result = plyara.parse_string(inputRules)
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


if __name__ == '__main__':
    unittest.main()
