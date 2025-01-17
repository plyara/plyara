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
import importlib.resources
import json
import unittest

import plyara.core
from plyara.exceptions import ParseTypeError
from plyara.utils import rebuild_yara_rule


class TestGithubIssues(unittest.TestCase):
    """Check that any fixes for reported issues remain fixed."""

    def setUp(self):
        self.data = importlib.resources.files('tests.data.issues')
        self.parser = plyara.core.Plyara()
        # self.maxDiff = None

    # Reference: https://github.com/plyara/plyara/issues/63
    def test_issue_63(self):
        input_string = self.data.joinpath('comment_only.yar').read_text()

        result = self.parser.parse_string(input_string)

        self.assertEqual(result, list())

    # Reference: https://github.com/plyara/plyara/issues/99
    def test_issue_99(self):
        input_string1 = self.data.joinpath('issue99_1.yar').read_text()
        input_string2 = self.data.joinpath('issue99_2.yar').read_text()
        rules = list()

        for input_string in [input_string1, input_string2]:
            yararules = self.parser.parse_string(input_string)
            self.assertEqual(len(yararules), 1)
            rules += yararules
            self.parser.clear()
        self.assertEqual(len(rules), 2)

    # Reference: https://github.com/plyara/plyara/issues/107
    def test_issue_107(self):
        input_string = self.data.joinpath('issue107.yar').read_text()

        result = self.parser.parse_string(input_string)

        expected = ['(', '#TEST1', '>', '5', ')', 'and', '(', '#test2', '>', '5', ')']

        self.assertEqual(result[0]['condition_terms'], expected)

    # Reference: https://github.com/plyara/plyara/issues/109
    def test_issue_109(self):
        input_string = self.data.joinpath('issue109.yar').read_text()
        test_result = self.data.joinpath('issue109_good_enough.yar').read_text()

        results = self.parser.parse_string(input_string)

        rebuilt_rules = rebuild_yara_rule(results[0])

        self.assertEqual(test_result, rebuilt_rules)

    # Reference: https://github.com/plyara/plyara/issues/112
    def test_issue_112(self):
        input_string = self.data.joinpath('issue112.yar').read_text()

        correct = {
            'minus_bad': ['$str_bef', 'in', '(', '@str_after', '-', '512', '..', '@str_after', ')'],
            'minus_good': ['$str_bef', 'in', '(', '@str_after', '-', '512', '..', '@str_after', ')'],
            'minus_very_bad': ['$str_bef', 'in', '(', '@str_after', '-', '-', '512', '..', '@str_after', ')'],
            'minus_very_very_bad': ['$str_bef', 'in', '(', '@str_after', '-', '-', '512', '..', '@str_after', ')'],
            'minus_bad_hexnum': ['$str_bef', 'in', '(', '@str_after', '-', '0x200', '..', '@str_after', ')'],
            'minus_good_hexnum': ['$str_bef', 'in', '(', '@str_after', '-', '0x200', '..', '@str_after', ')'],
            'minus_very_bad_hexnum': ['$str_bef', 'in', '(', '@str_after', '-', '-', '0x200', '..', '@str_after', ')'],
            'minus_very_very_bad_hexnum': [
                '$str_bef',
                'in',
                '(',
                '@str_after',
                '-',
                '-',
                '0x200',
                '..',
                '@str_after',
                ')'
            ]
        }

        result = self.parser.parse_string(input_string)

        for rule in result:
            rule_name = rule['rule_name']
            with self.subTest(rulename=rule_name):
                self.assertListEqual(rule['condition_terms'], correct[rule_name])

    # Reference: https://github.com/plyara/plyara/issues/115
    def test_issue_115(self):
        input_string = self.data.joinpath('issue115.yar').read_text()

        correct = {
            'bad_parsed_subtraction': ['@a', '-', '@b', '<', '128'],
            'good_parsed_addition': ['@a', '+', '@b', '<', '128'],
            'rule_extra_empty_line': ['@b', '-', '@a', '<', '128']
        }

        result = self.parser.parse_string(input_string)

        for rule in result:
            rule_name = rule['rule_name']
            with self.subTest(rulename=rule_name):
                self.assertListEqual(rule['condition_terms'], correct[rule_name])

    # Reference: https://github.com/plyara/plyara/issues/118
    def test_issue_118(self):
        """Check that clearing the parser works after an exception has been raised."""
        error_message = 'Unknown text strings: for token of type SECTIONSTRINGS on line 4'
        input_string = self.data.joinpath('issue118.yar').read_text()

        for i in range(4):
            with self.subTest(iteration=i):
                try:
                    _ = self.parser.parse_string(input_string)
                except ParseTypeError as e:
                    self.assertEqual(str(e), error_message)
                    self.parser.clear()

    # Reference: https://github.com/plyara/plyara/issues/141
    def test_issue_141_store_raw_sections_true(self):
        """Check when store_raw_sections at the default."""
        input_string = self.data.joinpath('issue141.yar').read_text()

        parsed_rules = self.parser.parse_string(input_string)

        for i, rule in enumerate(parsed_rules):
            with self.subTest(rulenum=i):
                if i == 0:
                    self.assertIsNone(rule.get('imports'))
                elif i == 1:
                    self.assertEqual(rule.get('imports'), ['pe'])

    # Reference: https://github.com/plyara/plyara/issues/141
    def test_issue_141_store_raw_sections_false(self):
        """Check when store_raw_sections set to False."""
        input_string = self.data.joinpath('issue141.yar').read_text()

        parser = plyara.core.Plyara(store_raw_sections=False)
        parsed_rules = parser.parse_string(input_string)

        for i, rule in enumerate(parsed_rules):
            with self.subTest(rulenum=i):
                if i == 0:
                    self.assertIsNone(rule.get('imports'))
                elif i == 1:
                    self.assertEqual(rule.get('imports'), ['pe'])

    # Reference: https://github.com/plyara/plyara/issues/143
    def test_issue_143(self):
        """Check whether xor modifier with hexnum range is parsed correctly."""
        input_string = self.data.joinpath('issue143.yar').read_text()

        parsed_rules = self.parser.parse_string(input_string)

        strings = parsed_rules[0].get('strings')
        self.assertIsInstance(strings, list)

        modifier = strings[0].get('modifiers', list())[0]
        self.assertEqual(modifier, 'xor(0x01-0xff)')

    # Reference: https://github.com/plyara/plyara/issues/144
    # Reference: https://github.com/CybercentreCanada/assemblyline/issues/231
    def test_issue_144(self):
        """Check whether negative numbers are parsed correctly in the meta section."""
        input_string = self.data.joinpath('issue144.yar').read_text()

        parsed_rules = self.parser.parse_string(input_string)

        metadata = parsed_rules[0].get('metadata')
        self.assertIsInstance(metadata, list)

        quality = [entry['quality'] for entry in metadata if 'quality' in entry]
        self.assertListEqual(quality, [-5])

    # Reference: https://github.com/plyara/plyara/issues/145
    def test_issue_145(self):
        """Check correct parsing for PR#130 changes."""
        input_string = self.data.joinpath('issue145.yar').read_text()

        parsed_rules = self.parser.parse_string(input_string)

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

    # Reference: https://github.com/plyara/plyara/issues/150
    def test_issue_150(self):
        """Check that comments between rules are discarded and not attached to a rule."""
        input_string = self.data.joinpath('issue150.yar').read_text()

        parsed_rules = self.parser.parse_string(input_string)

        for rule in parsed_rules:
            rulename = rule.get('rule_name')
            with self.subTest(rulenum=rulename):
                self.assertIsNone(rule.get('comments'))

    # Reference: https://github.com/plyara/plyara/issues/153
    def test_issue_153(self):
        """Check that bytestring comments have the correct line number."""
        input_string = self.data.joinpath('issue153.yar').read_text()
        expected = [5, 4]

        parser = plyara.core.Plyara(testmode=True)
        _ = parser.parse_string(input_string)

        for i, record in enumerate(parser._comment_record):
            with self.subTest(i=i):
                self.assertEqual(record.lineno, expected[i])

    # Reference: https://github.com/plyara/plyara/issues/156
    def test_issue_156(self):
        """Check that bytestring comments have the correct line number and correct end line number."""
        input_string = self.data.joinpath('issue156.yar').read_text()
        expected = json.loads(self.data.joinpath('issue156.json').read_text())

        parser = plyara.core.Plyara(testmode=True)
        result = parser.parse_string(input_string).pop()

        comments = list()
        for r in parser._comment_record:
            record = r.__dict__
            record.pop('lexer')
            comments.append(record)
        comments = sorted(comments, key=lambda x: x['lineno'])

        self.assertListEqual(comments, expected)

        # Check if the rule has the correct stop line
        self.assertIs(result['stop_line'], 17)


if __name__ == '__main__':
    unittest.main()
