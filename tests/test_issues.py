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
"""Unit tests for plyara Github issue fixes."""
import pathlib
import unittest

from plyara.core import Plyara
from plyara.exceptions import ParseTypeError
from plyara.utils import rebuild_yara_rule

DATA_DIR = pathlib.Path(__file__).parent.joinpath('data')


class TestGithubIssues(unittest.TestCase):
    """Check that any fixes for reported issues remain fixed."""

    # Reference: https://github.com/plyara/plyara/issues/63
    def issue_63(self):
        input_string = DATA_DIR.joinpath('comment_only.yar').read_text()

        plyara = Plyara()
        result = plyara.parse_string(input_string)

        self.assertEqual(result, list())

    # Reference: https://github.com/plyara/plyara/issues/99
    def issue_99(self):
        input_string1 = DATA_DIR.joinpath('issue99_1.yar').read_text()
        input_string2 = DATA_DIR.joinpath('issue99_2.yar').read_text()
        rules = list()
        plyara = Plyara()

        for input_string in [input_string1, input_string2]:
            yararules = plyara.parse_string(input_string)
            self.assertEqual(len(yararules), 1)
            rules += yararules
            plyara.clear()
        self.assertEqual(len(rules), 2)

    # Reference: https://github.com/plyara/plyara/issues/107
    def issue_107(self):
        input_string = DATA_DIR.joinpath('issue107.yar').read_text()

        plyara = Plyara()
        result = plyara.parse_string(input_string)

        expected = ['(', '#TEST1', '>', '5', ')', 'and', '(', '#test2', '>', '5', ')']

        self.assertEqual(result.rules[0]['condition_terms'], expected)

    # Reference: https://github.com/plyara/plyara/issues/109
    def issue_109(self):
        input_string = DATA_DIR.joinpath('issue109.yar').read_text()
        test_result = DATA_DIR.joinpath('issue109_good_enough.yar').read_text()

        plyara = Plyara()
        plyara.parse_string(input_string)

        rebuilt_rules = rebuild_yara_rule(plyara.rules[0])

        self.assertEqual(test_result, rebuilt_rules)

    # Reference: https://github.com/plyara/plyara/issues/112
    def issue_112(self):
        input_string = DATA_DIR.joinpath('issue112.yar').read_text()

        correct = {
            'minus_bad': ['$str_bef', 'in', '(', '@str_after', '-', '512', '..', '@str_after', ')'],
            'minus_good': ['$str_bef', 'in', '(', '@str_after', '-', '512', '..', '@str_after', ')'],
            'minus_very_bad': ['$str_bef', 'in', '(', '@str_after', '-', '-512', '..', '@str_after', ')'],
            'minus_very_very_bad': ['$str_bef', 'in', '(', '@str_after', '-', '-512', '..', '@str_after', ')'],
            'minus_bad_hexnum': ['$str_bef', 'in', '(', '@str_after', '-', '0x200', '..', '@str_after', ')'],
            'minus_good_hexnum': ['$str_bef', 'in', '(', '@str_after', '-', '0x200', '..', '@str_after', ')'],
            'minus_very_bad_hexnum': ['$str_bef', 'in', '(', '@str_after', '-', '-0x200', '..', '@str_after', ')'],
            'minus_very_very_bad_hexnum': ['$str_bef', 'in', '(', '@str_after', '-', '-0x200', '..', '@str_after', ')']
        }

        plyara = Plyara()
        result = plyara.parse_string(input_string)

        for rule in result.rules:
            rule_name = rule['rule_name']
            with self.subTest(rulename=rule_name):
                self.assertListEqual(rule['condition_terms'], correct[rule_name])

    # Reference: https://github.com/plyara/plyara/issues/115
    def issue_115(self):
        input_string = DATA_DIR.joinpath('issue115.yar').read_text()

        correct = {
            'bad_parsed_subtraction': ['@a', '+', '@b', '<', '128'],
            'good_parsed_addition': ['@a', '+', '@b', '<', '128'],
            'rule_extra_empty_line': ['@b', '-', '@a', '<', '128']
        }

        plyara = Plyara()
        result = plyara.parse_string(input_string)

        for rule in result.rules:
            rule_name = rule['rule_name']
            with self.subTest(rulename=rule_name):
                self.assertListEqual(rule['condition_terms'], correct[rule_name])

    # Reference: https://github.com/plyara/plyara/issues/118
    def issue_118(self):
        """Check that clearing the parser works after an exception has been raised."""
        input_string = DATA_DIR.joinpath('issue118.yar').read_text()

        plyara = Plyara()

        for i in range(4):
            with self.subTest(iteration=i):
                with self.assertRaises(ParseTypeError) as e:
                    _ = plyara.parse_string(input_string)

                self.assertEqual(str(e), 'Unknown text strings: for token of type SECTIONSTRINGS on line 5')
                plyara.clear()

    # Reference: https://github.com/plyara/plyara/issues/141
    def issue_141_store_raw_sections_true(self):
        """Check when store_raw_sections at the default."""
        input_string = DATA_DIR.joinpath('issue141.yar').read_text()

        plyara = Plyara()
        parsed_rules = plyara.parse_string(input_string)

        for i, rule in enumerate(parsed_rules):
            with self.subTest(rulenum=i):
                if i == 0:
                    self.assertIsNone(rule.get('imports'))
                elif i == 1:
                    self.assertEqual(rule.get('imports'), ['pe'])

    # Reference: https://github.com/plyara/plyara/issues/141
    def issue_141_store_raw_sections_false(self):
        """Check when store_raw_sections set to False."""
        input_string = DATA_DIR.joinpath('issue141.yar').read_text()

        plyara = Plyara(store_raw_sections=False)
        parsed_rules = plyara.parse_string(input_string)

        for i, rule in enumerate(parsed_rules):
            with self.subTest(rulenum=i):
                if i == 0:
                    self.assertIsNone(rule.get('imports'))
                elif i == 1:
                    self.assertEqual(rule.get('imports'), ['pe'])

    # Reference: https://github.com/plyara/plyara/issues/143
    def issue_143(self):
        """Check whether xor modifier with hexnum range is parsed correctly."""
        input_string = DATA_DIR.joinpath('issue143.yar').read_text()

        plyara = Plyara()
        parsed_rules = plyara.parse_string(input_string)

        strings = parsed_rules[0].get('strings')
        self.assertIsInstance(strings, list)

        modifier = strings[0].get('modifiers', list())[0]
        self.assertEqual(modifier, 'xor(0x01-0xff)')

    # Reference: https://github.com/plyara/plyara/issues/144
    # Reference: https://github.com/CybercentreCanada/assemblyline/issues/231
    def issue_144(self):
        """Check whether negative numbers are parsed correctly in the meta section."""
        input_string = DATA_DIR.joinpath('issue144.yar').read_text()

        plyara = Plyara()
        parsed_rules = plyara.parse_string(input_string)

        metadata = parsed_rules[0].get('metadata')
        self.assertIsInstance(metadata, list)

        quality = [entry['quality'] for entry in metadata if 'quality' in entry]
        self.assertDictEqual(quality, [-5])

    # Reference: https://github.com/plyara/plyara/issues/145
    def issue_145(self):
        """Check correct parsing for PR#130 changes."""
        input_string = DATA_DIR.joinpath('issue145.yar').read_text()

        plyara = Plyara()
        parsed_rules = plyara.parse_string(input_string)

        for rule in parsed_rules:
            rulename = rule.get('rule_name')
            with self.subTest(rulenum=rulename):
                if rulename == 'test1':
                    bv = rule['strings'][0]['value']
                    self.assertEqual(bv, '{ AA AA ~AA }')
                elif rulename == 'test2':
                    bv = rule['strings'][0]['value']
                    self.assertEqual(bv, '{ AA AA~AA }')
                elif rulename == 'test3':
                    md = rule['metadata'][0]['one']
                    self.assertEqual(md, 0)
                elif rulename == 'test4':
                    ct = rule['condition_terms']
                    self.assertListEqual(ct, ['-', '0.5'])
                elif rulename == 'test5':
                    ct = rule['condition_terms']
                    self.assertListEqual(ct, ['-', '1.5'])


if __name__ == '__main__':
    unittest.main()
