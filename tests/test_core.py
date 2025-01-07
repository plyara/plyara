# Copyright 2014 Christian Buia
# Copyright 2025 plyara Maintainers
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
"""Unit test plyara core module."""
import binascii
import concurrent.futures
import contextlib
import importlib.resources
import unittest

import plyara.core
from plyara.core import Plyara
from plyara.exceptions import ParseTypeError, ParseValueError


class TestImports(unittest.TestCase):
    """Check parsing of import statements."""

    def setUp(self):
        self.parser = plyara.core.Plyara()
        self.data = importlib.resources.files('tests.data.imports')

    def test_import_pe(self):
        """Check parsing of pe module import."""
        input_string = self.data.joinpath('import_ruleset_pe.yar').read_text()

        result = self.parser.parse_string(input_string)

        for rule in result:
            self.assertIn('pe', rule['imports'])

    def test_import_elf(self):
        """Check parsing of elf module import."""
        input_string = self.data.joinpath('import_ruleset_elf.yar').read_text()

        result = self.parser.parse_string(input_string)

        for rule in result:
            self.assertIn('elf', rule['imports'])

    def test_import_cuckoo(self):
        """Check parsing of cuckoo module import."""
        input_string = self.data.joinpath('import_ruleset_cuckoo.yar').read_text()

        result = self.parser.parse_string(input_string)

        for rule in result:
            self.assertIn('cuckoo', rule['imports'])

    def test_import_magic(self):
        """Check parsing of magic module import."""
        input_string = self.data.joinpath('import_ruleset_magic.yar').read_text()

        result = self.parser.parse_string(input_string)

        for rule in result:
            self.assertIn('magic', rule['imports'])

    def test_import_hash(self):
        """Check parsing of hash module import."""
        input_string = self.data.joinpath('import_ruleset_hash.yar').read_text()

        result = self.parser.parse_string(input_string)

        for rule in result:
            self.assertIn('hash', rule['imports'])

    def test_import_math(self):
        """Check parsing of math module import."""
        input_string = self.data.joinpath('import_ruleset_math.yar').read_text()

        result = self.parser.parse_string(input_string)

        for rule in result:
            self.assertIn('math', rule['imports'])

    def test_import_dotnet(self):
        """Check parsing of dotnet module import."""
        input_string = self.data.joinpath('import_ruleset_dotnet.yar').read_text()

        result = self.parser.parse_string(input_string)

        for rule in result:
            self.assertIn('dotnet', rule['imports'])

    def test_import_androguard(self):
        """Check parsing of androguard module import."""
        input_string = self.data.joinpath('import_ruleset_androguard.yar').read_text()

        result = self.parser.parse_string(input_string)

        for rule in result:
            self.assertIn('androguard', rule['imports'])


class TestStoreRawSections(unittest.TestCase):
    """Test various raw sections are stored correctly."""

    def setUp(self):
        self.data = importlib.resources.files('tests.data.core')

    def test_raw_meta(self):
        """Test that the raw meta result is as expected."""
        expected = self.data.joinpath('raw_sections_meta.txt').read_text().strip()
        test_rule = self.data.joinpath('raw_sections.yar').read_text()

        parser = plyara.core.Plyara()
        result = parser.parse_string(test_rule)[0]

        raw = result.get('raw_meta')
        section = binascii.hexlify(raw.encode()).decode()
        self.assertEqual(section, expected)

    def test_raw_strings(self):
        """Test that the raw strings result is as expected."""
        expected = self.data.joinpath('raw_sections_strings.txt').read_text().strip()
        test_rule = self.data.joinpath('raw_sections.yar').read_text()

        parser = plyara.core.Plyara()
        result = parser.parse_string(test_rule)[0]

        raw = result.get('raw_strings')
        section = binascii.hexlify(raw.encode()).decode()
        self.assertEqual(section, expected)

    def test_raw_condition(self):
        """Test that the raw condition result is as expected."""
        expected = self.data.joinpath('raw_sections_condition.txt').read_text().strip()
        test_rule = self.data.joinpath('raw_sections.yar').read_text()

        parser = plyara.core.Plyara()
        result = parser.parse_string(test_rule)[0]

        raw = result.get('raw_condition')
        section = binascii.hexlify(raw.encode()).decode()
        self.assertEqual(section, expected)

    def test_no_raw_sections(self):
        """Test that raw sections are not saved when init parameter is False."""
        test_rule = self.data.joinpath('raw_sections.yar').read_text()

        parser = plyara.core.Plyara(store_raw_sections=False)
        result = parser.parse_string(test_rule)[0]

        self.assertIsNone(result.get('raw_meta'))
        self.assertIsNone(result.get('raw_strings'))
        self.assertIsNone(result.get('raw_condition'))


class TestRuleParser(unittest.TestCase):
    """Check yara rule parsing."""

    def setUp(self):
        self.parser = plyara.core.Plyara()
        self.data = importlib.resources.files('tests.data.core')
        self.common = importlib.resources.files('tests.data.common')
        self.unhandled_rule = 'Unhandled Test Rule: {}'

    def test_comments(self):
        """Check that all comment locations in a rule are parsed correctly."""
        input_string = self.data.joinpath('comments_ruleset.yar').read_text()
        lcomments = [
            "// nameline",
            "// openbrace",
            "// metasection",
            "// metakv",
            "// stringssection",
            "// bytestring",
            "// conditionsection",
            "// conditioninternal1",
            "// conditioninternal2",
            "// conditioninternal3",
            "// condition",
            "// closebrace",
            "// bytestringinternal2",
            "// bytestringinternal1"
        ]
        mcomments = [
            "/* nameline\n                         secondline */",
            "/* openbrace\n       secondline */",
            "/* metasection\n                secondline */",
            "/* metakv\n                                       secondline */",
            "/* stringssection\n                secondline */",
            "/* bytestring\n                                     secondline */",
            "/* conditionsection\n                      secondline */",
            "/* conditioninternal1\n                                                       secondline */",
            "/* condition\n                                                       secondline */",
            "/* closebrace\n       secondline */",
            "/* bytestringinternal1\n                                     secondline */"
        ]
        expected = [lcomments, mcomments]

        result = self.parser.parse_string(input_string)

        for i, entry in enumerate(result):
            with self.subTest(i=i):
                comments = entry.get('comments')

                self.assertListEqual(comments, expected[i])

    def test_comments_crlf(self):
        """Check that all comment locations in a rule are parsed correctly in CRLF file."""
        input_string = self.data.joinpath('comments_ruleset_crlf.yar').read_bytes().decode()
        lcomments = [
            "// nameline",
            "// openbrace",
            "// metasection",
            "// metakv",
            "// stringssection",
            "// bytestring",
            "// conditionsection",
            "// conditioninternal1",
            "// conditioninternal2",
            "// conditioninternal3",
            "// condition",
            "// closebrace",
            "// bytestringinternal2",
            "// bytestringinternal1"
        ]
        mcomments = [
            "/* nameline\r\n                         secondline */",
            "/* openbrace\r\n       secondline */",
            "/* metasection\r\n                secondline */",
            "/* metakv\r\n                                       secondline */",
            "/* stringssection\r\n                secondline */",
            "/* bytestring\r\n                                     secondline */",
            "/* conditionsection\r\n                      secondline */",
            "/* conditioninternal1\r\n                                                       secondline */",
            "/* condition\r\n                                                       secondline */",
            "/* closebrace\r\n       secondline */",
            "/* bytestringinternal1\r\n                                     secondline */"
        ]
        expected = [lcomments, mcomments]

        result = self.parser.parse_string(input_string)

        for i, entry in enumerate(result):
            with self.subTest(i=i):
                comments = entry.get('comments')

                self.assertListEqual(comments, expected[i])

    def test_scopes(self):
        input_string = self.data.joinpath('scope_ruleset.yar').read_text()

        result = self.parser.parse_string(input_string)

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
                raise AssertionError(self.unhandled_rule.format(rulename))

    def test_tags(self):
        input_string = self.data.joinpath('tag_ruleset.yar').read_text()

        result = self.parser.parse_string(input_string)

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
                raise AssertionError(self.unhandled_rule.format(rulename))

    def test_metadata(self):
        input_string = self.data.joinpath('metadata_ruleset.yar').read_text()

        result = self.parser.parse_string(input_string)

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

            elif rulename == 'NegativeNumberMetadata':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0][0], 'negative')
                self.assertIs(kv_list[0][1], -5)

            else:
                raise AssertionError(self.unhandled_rule.format(rulename))

    def test_strings(self):
        input_string = self.data.joinpath('string_ruleset.yar').read_text()

        result = self.parser.parse_string(input_string)

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

            elif rulename == 'DoubleQuote':
                self.assertEqual(kv, [{'name': '$text_string', 'value': r'foobar\"', 'type': 'text'}])

            elif rulename == 'HorizontalTab':
                self.assertEqual(kv, [{'name': '$text_string', 'value': r'foo\tbar', 'type': 'text'}])

            elif rulename == 'Newline':
                self.assertEqual(kv, [{'name': '$text_string', 'value': r'foo\nbar', 'type': 'text'}])

            elif rulename == 'HexEscape':
                self.assertEqual(kv, [{'name': '$text_string', 'value': r'foo\x00bar', 'type': 'text'}])

            else:
                raise AssertionError(self.unhandled_rule.format(rulename))

    def test_condition_only(self):
        """Test that a rule with only conditions is parsed correctly."""
        input_string = self.data.joinpath('only_condition.yar').read_text()

        result = self.parser.parse_string(input_string)

        for entry in result:
            condition_terms = entry.get('condition_terms')
            self.assertListEqual(condition_terms, ['true'])

            raw_condition = entry.get('raw_condition')
            self.assertEqual(raw_condition, 'condition: true')

    def test_private_bytestring_modifier(self):
        """Check if the private bytestring modifier is parsed correctly."""
        input_rule = r'''
        rule sample {
            strings:
                $a = { ABABABAB } private
            condition:
                $a
        }
        '''

        result = self.parser.parse_string(input_rule)

        modifier = result[0]['strings'][0]['modifiers'][0]
        self.assertEqual(modifier, 'private')

    def test_illegal_rule_name(self):
        """Check if illegal rule name with '.' character."""
        inputRules = r'''
        rule sam.ple {
            condition:
                true
        }
        '''

        plyara = Plyara()
        with self.assertRaises(ParseTypeError):
            plyara.parse_string(inputRules)

    def test_illegal_rule_tag(self):
        """Check if illegal rule tag with '.' character."""
        inputRules = r'''
        rule badtag : inva.lid
        {
            condition:
                true
        }
        '''

        plyara = Plyara()
        with self.assertRaises(ParseTypeError):
            plyara.parse_string(inputRules)

    def test_string_illegal_character(self):
        """Check if illegal character is in a string."""
        inputRules = r'''
        rule sample {
            strings:
                $ = "foo
                bar"
            condition:
                all of them
        }
        '''

        plyara = Plyara()
        with self.assertRaises(ParseTypeError):
            plyara.parse_string(inputRules)

    def test_string_bad_escaped_hex(self):
        inputRules = r'''
        rule sample {
            strings:
                $ = "foo\xZZbar"
            condition:
                all of them
        }
        '''

        plyara = Plyara()
        with self.assertRaises(ParseTypeError):
            plyara.parse_string(inputRules)

    def test_string_invalid_escape(self):
        inputRules = r'''
        rule sample {
            strings:
                $ = "foo\gbar"
            condition:
                all of them
        }
        '''

        plyara = Plyara()
        with self.assertRaises(ParseTypeError):
            plyara.parse_string(inputRules)

    def test_illegal_stringname_prefix(self):
        input_rule = r'''
        rule sample
        {
            strings:
                $-a = "test"
            condition:
                any of them
        }
        '''

        with self.assertRaises(ParseTypeError):
            self.parser.parse_string(input_rule)

    def test_illegal_stringname_infix(self):
        input_rule = r'''
        rule sample
        {
            strings:
                $a-b = "test"
            condition:
                any of them
        }
        '''

        with self.assertRaises(ParseTypeError):
            self.parser.parse_string(input_rule)

    def test_illegal_stringname_suffix(self):
        input_rule = r'''
        rule sample
        {
            strings:
                $a- = "test"
            condition:
                any of them
        }
        '''

        with self.assertRaises(ParseTypeError):
            self.parser.parse_string(input_rule)

    def test_duplicate_string_name(self):
        input_rule = r'''
        rule sample
        {
            strings:
                $a = "test"
                $a = "testtest"
            condition:
                $a
        }
        '''

        with self.assertRaises(ParseTypeError):
            self.parser.parse_string(input_rule)

    def test_conditions(self):
        input_string = self.data.joinpath('condition_ruleset.yar').read_text()

        # Just checking for parsing errors
        self.parser.parse_string(input_string)

    def test_include(self):
        input_string = self.data.joinpath('include_ruleset.yar').read_text()

        result = self.parser.parse_string(input_string)
        self.assertEqual(result[0]['includes'], ['string_ruleset.yar'])

    def test_include_statements(self):
        self.parser.parse_string('include "file1.yara"\ninclude "file2.yara"\ninclude "file3.yara"')
        self.assertEqual(len(self.parser.includes), 3)

    def test_rules_from_yara_project(self):
        input_rules = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        plyara = Plyara()
        output = plyara.parse_string(input_rules)

        self.assertEqual(len(output), 293)

    def test_multiple_threads(self):
        input_rules = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        def parse_rules(rules):
            plyara = Plyara()
            return plyara.parse_string(input_rules)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
            futs = [e.submit(parse_rules, input_rules) for _ in range(4)]
            for fut in concurrent.futures.as_completed(futs):
                self.assertEqual(len(fut.result()), 293)

    def test_clear(self):
        # instantiate parser
        parser = Plyara()

        # open a ruleset with one or more rules
        input_rules = self.data.joinpath('test_ruleset_2_rules.yar').read_text()

        # parse the rules
        parser.parse_string(input_rules)

        # clear the parser's state
        parser.clear()

        # has lineno been reset
        self.assertEqual(parser.lexer.lineno, 1)

        # open a ruleset with one rule
        input_rules = self.data.joinpath('test_ruleset_1_rule.yar').read_text()

        # parse the rules
        result = parser.parse_string(input_rules)

        # does the result contain just the rule from the second parse
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['rule_name'], 'rule_one')

    def test_find_imports_in_condition(self):
        """Check if the finder function works across all testing rules."""
        input_rulesets = self.data.glob('import_ruleset_*.yar')

        for ruleset in input_rulesets:
            import_type = ruleset.name[15:-4]
            with self.subTest(import_type=import_type):
                parser = Plyara()
                input_string = ruleset.read_text()
                parser._raw_input = input_string
                parser.parser.parse(input_string, lexer=parser.lexer)

                imports = parser._find_imports_in_condition(parser.imports, parser.rules[0]['condition_terms'])

                self.assertEqual(imports, [import_type])


class TestRuleParserKVMeta(unittest.TestCase):
    """Check metadata key value pairs."""

    def setUp(self):
        self.parser = plyara.core.Plyara(meta_as_kv=True)
        self.data = importlib.resources.files('tests.data.core')

    def test_meta_kv(self):
        input_string = self.data.joinpath('metakv_test.yar').read_text()
        reference1 = {'author': 'Malware Utkonos',
                      'date': '2020-01-04',
                      'tlp': 'Green'}
        reference2 = {'author': 'Someone else',
                      'date': '2020-01-04',
                      'tlp': 'Green'}

        result = self.parser.parse_string(input_string)

        self.assertEqual(result[0]['metadata_kv'], reference1)
        self.assertEqual(result[1]['metadata_kv'], reference2)


class TestYaraRules(unittest.TestCase):
    """Check as wide a variety of yara rules as possible."""

    def setUp(self):
        self.parser = plyara.core.Plyara()
        self.data = importlib.resources.files('tests.data.core')

    def test_multiple_rules(self):
        input_string = '''
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
        result = plyara.parse_string(input_string)

        self.assertEqual(len(result), 3)
        kv_list = [(k,) + (v, ) for dic in result[0]['metadata'] for k, v in dic.items()]
        self.assertEqual(kv_list[0][0], 'author')
        self.assertEqual(kv_list[0][1], 'Andrés Iniesta')
        self.assertEqual(kv_list[1][0], 'date')
        self.assertEqual(kv_list[1][1], '2015-01-01')
        self.assertEqual([x['name'] for x in result[0]['strings']], ['$a', '$b'])

    def disable_test_rule_name_imports_and_scopes(self):
        input_string_nis = r'''
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
        result = plyara.parse_string(input_string_nis)

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

        plyara1 = Plyara(import_effects=True)
        result1 = plyara1.parse_string(input1)

        plyara2 = Plyara(import_effects=True)
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
        input_rule = r'''
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
        result = plyara.parse_string(input_rule)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['rule_name'], 'testName')

    def test_store_raw(self):
        input_rule = r'''
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
        result = plyara.parse_string(input_rule)

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
        input_tags = r'''
        rule eleven: tag1 {meta: i = "j" strings: $a = "b" condition: true }

        rule twelve : tag1 tag2 {meta: i = "j" strings: $a = "b" condition: true }
        '''

        plyara = Plyara()
        result = plyara.parse_string(input_tags)

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
        input_rules = r'''
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
        result = plyara.parse_string(input_rules)

        for rule in result:
            rule_name = rule['rule_name']
            if rule_name == 'thirteen':
                self.assertEqual(len(rule['metadata']), 3)

    def test_bytestring(self):
        input_rules = r'''
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
            $a13 = { E2AAAAAA ~00 BBBBBBFB }
            $a14 = { E2AAAAAA~00 BBBBBBFB }
            $a15 = { E2AAAAAA~00BBBBBBFB }

        condition:
            any of them
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(input_rules)

        self.assertEqual(len(result), 1)
        for rule in result:
            rule_name = rule['rule_name']
            if rule_name == 'testName':
                self.assertEqual(len(rule['strings']), 15)
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
                self.assertEqual(rule['strings'][12]['value'], '{ E2AAAAAA ~00 BBBBBBFB }')
                self.assertEqual(rule['strings'][13]['value'], '{ E2AAAAAA~00 BBBBBBFB }')
                self.assertEqual(rule['strings'][14]['value'], '{ E2AAAAAA~00BBBBBBFB }')

    @staticmethod
    def test_nested_bytestring():
        input_rules = r'''
        rule sample {
            strings:
                $ = { 4D 5A ( 90 ( 00 | 01 ) | 89 ) }
            condition:
                all of them
        }
        '''

        plyara = Plyara()
        plyara.parse_string(input_rules)

    def test_bytestring_bad_jump(self):
        input_rules = r'''
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
            plyara.parse_string(input_rules)

    def test_bytestring_bad_group(self):
        input_rules = r'''
        rule sample {
            strings:
                $ = { 4D 5A ( 90 ( 00 | 01 ) | 89 ) ) }
            condition:
                all of them
        }
        '''

        plyara = Plyara()
        with self.assertRaises(ParseValueError):
            plyara.parse_string(input_rules)

    def test_bytestring_bad_hexchar(self):
        input_rules = r'''
        rule sample {
            strings:
                $ = { 4D 5X }
            condition:
                all of them
        }
        '''

        plyara = Plyara()
        with self.assertRaises(ParseTypeError):
            plyara.parse_string(input_rules)

    def test_rexstring(self):
        input_rules = r'''
        rule testName
        {
        strings:
            $a1 = /abc123 \d/i
            $a2 = /abc123 \d+/i // comment
            $a3 = /abc123 \d\/ afterspace/is // comment
            $a4 = /abc123 \d\/ afterspace/is nocase // comment
            $a5 = /abc123 \d\/ afterspace/nocase // comment
            $a6 = /abc123 \d\/ afterspace/nocase// comment

            /* It should only consume the regex pattern and not text modifiers
               or comment, as those will be parsed separately. */

        condition:
            any of them
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(input_rules)

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
                        self.assertEqual(rex_string['value'], '/abc123 \\d\\/ afterspace/is')
                    elif rex_string['name'] == '$a4':
                        self.assertEqual(rex_string['value'], '/abc123 \\d\\/ afterspace/is')
                        self.assertEqual(rex_string['modifiers'], ['nocase'])
                    elif rex_string['name'] in ['$a5', '$a6']:
                        self.assertEqual(rex_string['value'], '/abc123 \\d\\/ afterspace/')
                        self.assertEqual(rex_string['modifiers'], ['nocase'])
                    else:
                        self.assertFalse('Unknown string name...')

    def test_bad_regex_string_char(self):
        """Test if an illegal character in a regex string raises an exception."""
        input_string = self.data.joinpath('bad_regex_string_char.yar').read_text()

        with self.assertRaises(ParseTypeError):
            _ = self.parser.parse_string(input_string)

    def test_string(self):
        input_rules = r'''
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
        result = plyara.parse_string(input_rules)

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

    def test_raw_condition_contains_all_condition_text(self):
        input_rules = r'''
        rule testName {condition: any of them}
        '''

        plyara = Plyara()
        result = plyara.parse_string(input_rules)

        self.assertEqual(result[0]['raw_condition'], 'condition: any of them')

    def test_raw_strings_contains_all_string_text(self):
        input_rules = r'''
        rule testName {strings: $a = "1" condition: true}
        '''

        plyara = Plyara()
        result = plyara.parse_string(input_rules)

        self.assertEqual(result[0]['raw_strings'], 'strings: $a = "1" ')

    def test_raw_meta_contains_all_meta_text(self):
        input_rules = r'''
        rule testName {meta: author = "Test" condition: true}
        '''

        plyara = Plyara()
        result = plyara.parse_string(input_rules)

        self.assertEqual(result[0]['raw_meta'], 'meta: author = "Test" ')

        # strings after meta
        input_rules = r'''
        rule testName {meta: author = "Test" strings: $a = "1"}
        '''

        plyara = Plyara()
        result = plyara.parse_string(input_rules)

        self.assertEqual(result[0]['raw_meta'], 'meta: author = "Test" ')

    def test_illegal_char(self):
        """Test if an illegal character anywhere raises an exception."""
        input_string = self.data.joinpath('illegal_char.yar').read_text()

        with self.assertRaises(ParseTypeError):
            _ = self.parser.parse_string(input_string)

    def test_parse_file_without_rules_returns_empty_list(self):
        input_rules = str()

        plyara = Plyara()
        result = plyara.parse_string(input_rules)

        self.assertEqual(result, list())

    def test_bad_condition_string(self):
        input_string = self.data.joinpath('bad_condition_string.yar').read_text()

        plyara = Plyara()

        with self.assertRaises(ParseTypeError):
            plyara.parse_string(input_string)

    def test_lineno_incremented_by_newlines_in_bytestring(self):
        input_rules = r'''
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

        with contextlib.suppress(ParseTypeError):
            try:
                plyara.parse_string(input_rules)
            except ParseTypeError as e:
                self.assertEqual(7, e.lineno)
                raise e

    def test_lineno_incremented_by_windows_newlines_in_bytestring(self):
        input_rules = self.data.joinpath('windows_newline_ruleset_with_error.yar').read_text()

        plyara = Plyara()

        with self.assertRaises(ParseTypeError):
            try:
                plyara.parse_string(input_rules)
            except ParseTypeError as e:
                self.assertEqual(6, e.lineno)
                raise e

    def test_lineno_incremented_by_windows_newlines_in_comment(self):
        input_rules = self.data.joinpath('windows_newline_ruleset_comment.yar').read_text()

        plyara = Plyara()

        plyara.parse_string(input_rules)
        self.assertEqual(plyara.lexer.lineno, 13)

    def test_windows_CRNL(self):
        input_rules = self.data.joinpath('windows_newline_ruleset.yar').read_text()

        reference = [{'condition_terms': ['all', 'of', 'them'],
                      'raw_condition': "condition:\nall of them\n",
                      'raw_strings': "strings:\n$ = { 00\n      00 }\n",
                      'rule_name': 'sample',
                      'start_line': 1,
                      'stop_line': 8,
                      'strings': [{'name': '$',
                                   'type': 'byte',
                                   'value': '{ 00\n      00 }'}]}]

        plyara = Plyara()
        result = plyara.parse_string(input_rules)

        self.assertEqual(result, reference)

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

    def test_xor_modified_condition(self):
        """Check that various xor modifiers are parsed correctly."""
        input_rules = self.data.joinpath('xor_modifier_ruleset.yar').read_text()
        expected = [
            ['xor', 'wide'],
            ['xor(16)'],
            ['xor(16-128)'],
            ['xor(0x10)'],
            ['xor(0x10-0x80)'],
            ['xor(16-0x80)'],
            ['xor(0x10-64)']
        ]

        parser = plyara.core.Plyara()
        results = parser.parse_string(input_rules)

        for i, result in enumerate(results):
            with self.subTest(i=result.get('rule_name')):
                mods = result.get('strings')[0].get('modifiers')
                self.assertListEqual(mods, expected[i])

    def test_xor_modifier_whitespace(self):
        """Check that all whitespace variations are equivalently parsed."""
        input_rules = self.data.joinpath('xor_modifier_whitespace.yar').read_text()
        expected = 'xor(0x01-0xff)'

        parser = plyara.core.Plyara()
        results = parser.parse_string(input_rules)

        for result in results:
            with self.subTest(i=result.get('rule_name')):
                mod = result.get('strings')[0].get('modifiers')[0]
                self.assertEqual(mod, expected)

    def test_base64_modified_condition(self):
        """Check that various ba64 modifiers are parsed correctly."""
        input_rules = self.data.joinpath('base64_modifier_ruleset.yar').read_text()
        expected = [
            ['base64'],
            ['base64wide'],
            [r'base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")'],
            [r'base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")']
        ]

        parser = plyara.core.Plyara()
        results = parser.parse_string(input_rules)

        for i, result in enumerate(results):
            with self.subTest(i=result.get('rule_name')):
                mods = result.get('strings')[0].get('modifiers')
                self.assertListEqual(mods, expected[i])

    def test_duplicated_simple_modifier_xor(self):
        """Test that a duplicated string modifier raises an exception."""
        error_msg = r'Duplicate simple text string modifier xor on line \d'
        input_rule = r'''
        rule duplicate_modifier
        {
            strings:
                $a = "one" xor xor
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_duplicated_complex_simple_modifier_xor(self):
        """Test that a duplicated string modifiers of two types raises an exception."""
        error_msg = r'Duplicate complex xor text string modifier xor on line \d'
        input_rule = r'''
        rule duplicate_modifier
        {
            strings:
                $a = "one" xor xor(0x10)
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_duplicated_complex_simple_modifier_base64(self):
        """Test that a duplicated string modifiers of two types raises an exception."""
        error_msg = r'Duplicate complex base64 text string modifier base64 on line \d'
        input_rule = r'''
        rule duplicate_modifier
        {
            strings:
                $a = "one" base64 base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_duplicated_complex_simple_modifier_base64wide(self):
        """Test that a duplicated string modifiers of two types raises an exception."""
        error_msg = r'Duplicate complex base64wide text string modifier base64wide on line \d'
        input_rule = r'''
        rule duplicate_modifier
        {
            strings:
                $a = "one" base64wide base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_unexpected_xor(self):
        """Test that an xor modifier on the wrong string type raises an exception."""
        error_msg = r'Unknown text xor for token of type XOR_MOD on line \d'
        input_rule = r'''
        rule invalid_xor_modifier
        {
            strings:
                $a = /AA/ xor(500)
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_unexpected_base64(self):
        """Test that an base64 modifier on the wrong string type raises an exception."""
        error_msg = r'Unknown text base64 for token of type BASE64 on line \d'
        input_rule = r'''
        rule invalid_base64_modifier
        {
            strings:
                $a = /AA/ base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_unexpected_base64wide(self):
        """Test that an base64wide modifier on the wrong string type raises an exception."""
        error_msg = r'Unknown text base64wide for token of type BASE64WIDE on line \d'
        input_rule = r'''
        rule invalid_base64wide_modifier
        {
            strings:
                $a = /AA/ base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_invalid_modifier_combination_base64_nocase(self):
        """Test that incompatible modifiers raise an exception."""
        error_msg = r'Incompatible modifiers \[nocase, base64\] on line \d'
        input_rule = r'''
        rule base64_error_nocase
        {
            strings:
                $a = "one" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu") nocase
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_invalid_modifier_combination_base64_xor(self):
        """Test that incompatible modifiers raise an exception."""
        error_msg = r'Incompatible modifiers \[xor, base64\] on line \d'
        input_rule = r'''
        rule base64_error_xor
        {
            strings:
                $a = "one" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu") xor
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_invalid_modifier_combination_base64wide_nocase(self):
        """Test that incompatible modifiers raise an exception."""
        error_msg = r'Incompatible modifiers \[nocase, base64wide\] on line \d'
        input_rule = r'''
        rule base64wide_error_nocase
        {
            strings:
                $b = "two" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu") nocase
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_invalid_modifier_combination_base64wide_xor(self):
        """Test that incompatible modifiers raise an exception."""
        error_msg = r'Incompatible modifiers \[xor, base64wide\] on line \d'
        input_rule = r'''
        rule base64wide_error_xor
        {
            strings:
                $b = "two" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu") xor
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_base64_alphabet_length_too_long(self):
        """Test that a base64 alphabet is not more than 64 characters."""
        error_msg = r'Modifier base64 predicate too long: \d+ on line \d'
        input_rule = r'''
        rule base64_error_xor
        {
            strings:
                $a = "one" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstuxyz")
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_base64_alphabet_length_too_short(self):
        """Test that a base64 alphabet is not less than 64 characters."""
        error_msg = r'Modifier base64 predicate too short: \d+ on line \d'
        input_rule = r'''
        rule base64_error_xor
        {
            strings:
                $a = "one" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZ")
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_base64wide_alphabet_length_too_long(self):
        """Test that a base64wide alphabet is not more than 64 characters."""
        error_msg = r'Modifier base64wide predicate too long: \d+ on line \d'
        input_rule = r'''
        rule base64_error_xor
        {
            strings:
                $a = "two" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstuxyz")
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)

    def test_base64wide_alphabet_length_too_short(self):
        """Test that a base64wide alphabet is not less than 64 characters."""
        error_msg = r'Modifier base64wide predicate too short: \d+ on line \d'
        input_rule = r'''
        rule base64_error_xor
        {
            strings:
                $a = "two" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZ")
            condition:
                all of them
        }
        '''

        parser = plyara.core.Plyara()

        with self.assertRaisesRegex(ParseTypeError, error_msg):
            parser.parse_string(input_rule)


if __name__ == '__main__':
    unittest.main()
