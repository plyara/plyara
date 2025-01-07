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
"""Unit tests for plyara utility functions."""
import importlib.resources
import unittest

import plyara.core
from plyara.utils import generate_hash
from plyara.utils import rebuild_yara_rule


class TestUtilities(unittest.TestCase):
    """Check the various utility functions."""

    def setUp(self):
        """Prepare for utility unit testing."""
        self.parser = plyara.core.Plyara()
        self.data = importlib.resources.files('tests.data.utils')
        self.imports = importlib.resources.files('tests.data.imports')
        self.common = importlib.resources.files('tests.data.common')
        # self.maxDiff = None

    def test_generate_hash(self):
        input_string = self.data.joinpath('logic_collision_ruleset.yar').read_text()

        result = plyara.core.Plyara().parse_string(input_string)

        rule_mapping = {}

        for entry in result:
            rulename = entry['rule_name']
            setname, _ = rulename.split('_')
            rulehash = generate_hash(entry)

            if setname not in rule_mapping:
                rule_mapping[setname] = [rulehash]
            else:
                rule_mapping[setname].append(rulehash)

        for setname, hashvalues in rule_mapping.items():
            self.assertTrue(len(set(hashvalues)) == 1, 'Collision detection failure for {}'.format(setname))

    def test_generate_hash_output_legacy(self):
        rule_hashes = self.data.joinpath('rulehashes_legacy.txt').read_text().splitlines()
        # Rules containing "(1..#)" or similar iterators cause Unhandled String Count Condition errors
        input_string = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        results = plyara.core.Plyara().parse_string(input_string)

        for index, result in enumerate(results):
            rulehash = generate_hash(result, legacy=True)
            self.assertEqual(rulehash, rule_hashes[index])

    def test_generate_hash_output(self):
        rule_hashes = self.data.joinpath('rulehashes.txt').read_text().splitlines()
        # Rules containing "(1..#)" or similar iterators cause Unhandled String Count Condition errors
        input_string = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        results = plyara.core.Plyara().parse_string(input_string)

        for index, result in enumerate(results):
            rulehash = generate_hash(result)
            self.assertEqual(rulehash, rule_hashes[index])

    def test_rebuild_yara_rule(self):
        input_string = self.data.joinpath('rebuild_ruleset.yar').read_text(encoding='utf-8')
        test_result = self.data.joinpath('rebuild_ruleset_good_enough.yar').read_text(encoding='utf-8')

        result = plyara.core.Plyara().parse_string(input_string)

        rebuilt_rules = str()
        for rule in result:
            rebuilt_rules += rebuild_yara_rule(rule)

        self.assertEqual(test_result, rebuilt_rules)

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
        parsed = plyara.core.Plyara().parse_string(test_rule)
        for rule in parsed:
            unparsed = rebuild_yara_rule(rule)
            self.assertIn('string_value = "TEST STRING"', unparsed)
            self.assertIn('string_value = "DIFFERENT TEST STRING"', unparsed)
            self.assertIn('bool_value = true', unparsed)
            self.assertIn('bool_value = false', unparsed)
            self.assertIn('digit_value = 5', unparsed)
            self.assertIn('digit_value = 10', unparsed)


if __name__ == '__main__':
    unittest.main()
