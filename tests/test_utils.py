# Copyright 2014 Christian Buia
# Copyright 2024 plyara Maintainers
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
import pathlib
import unittest

from plyara.core import Plyara
from plyara.utils import generate_hash
from plyara.utils import rebuild_yara_rule
from plyara.utils import detect_imports, detect_dependencies
from plyara.utils import is_valid_rule_name, is_valid_rule_tag

data_dir = pathlib.Path('tests').joinpath('data')


class TestUtilities(unittest.TestCase):
    """Check the various utility functions."""

    def setUp(self):
        """Prepare for utility unit testing."""
        self.maxDiff = None

    def test_generate_hash(self):
        with data_dir.joinpath('logic_collision_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = Plyara().parse_string(inputString)

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

    def test_generate_hash_output(self):
        with data_dir.joinpath('rulehashes.txt').open('r') as fh:
            rule_hashes = fh.read().splitlines()

        with data_dir.joinpath('test_rules_from_yara_project.yar').open('r') as fh:
            # Rules containing "(1..#)" or similar iterators cause Unhandled String Count Condition errors
            inputString = fh.read()

        results = Plyara().parse_string(inputString)

        for index, result in enumerate(results):
            rulehash = generate_hash(result)
            self.assertEqual(rulehash, rule_hashes[index])

    # def test_generate_logic_hash(self):
    #     with data_dir.joinpath('logic_collision_ruleset_v2.0.0.yar').open('r') as fh:
    #         inputString = fh.read()

    #     result = Plyara().parse_string(inputString)

    #     rule_mapping = {}

    #     for entry in result:
    #         rulename = entry['rule_name']
    #         setname, _ = rulename.split('_')
    #         rulehash = generate_logic_hash(entry)

    #         if setname not in rule_mapping:
    #             rule_mapping[setname] = [rulehash]
    #         else:
    #             rule_mapping[setname].append(rulehash)

    #     for setname, hashvalues in rule_mapping.items():
    #         self.assertTrue(len(set(hashvalues)) == 1, 'Collision detection failure for {}'.format(setname))

    # def test_generate_logic_hash_output(self):
    #     with data_dir.joinpath('rulehashes_v2.0.0.txt').open('r') as fh:
    #         rule_hashes = fh.read().splitlines()

    #     with data_dir.joinpath('test_rules_from_yara_project.yar').open('r') as fh:
    #         # Rules containing "(1..#)" or similar iterators cause Unhandled String Count Condition errors
    #         inputString = fh.read()

    #     results = Plyara().parse_string(inputString)

    #     for index, result in enumerate(results):
    #         rulehash = generate_logic_hash(result)
    #         self.assertEqual(rulehash, rule_hashes[index])

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
        self.assertTrue(is_valid_rule_name('x' * 128))
        self.assertFalse(is_valid_rule_name('x' * 129))

    def test_is_valid_rule_tag(self):
        self.assertTrue(is_valid_rule_tag('test'))
        self.assertTrue(is_valid_rule_tag('test123'))
        self.assertTrue(is_valid_rule_tag('test_test'))
        self.assertTrue(is_valid_rule_tag('_test_'))
        self.assertTrue(is_valid_rule_tag('include_test'))
        self.assertFalse(is_valid_rule_tag('123test'))
        self.assertFalse(is_valid_rule_tag('123 test'))
        self.assertFalse(is_valid_rule_tag('test 123'))
        self.assertFalse(is_valid_rule_tag('test test'))
        self.assertFalse(is_valid_rule_tag('test-test'))
        self.assertFalse(is_valid_rule_tag('include'))
        self.assertFalse(is_valid_rule_tag('test!*@&*!&'))
        self.assertFalse(is_valid_rule_tag(''))
        self.assertTrue(is_valid_rule_tag('x' * 128))
        self.assertFalse(is_valid_rule_tag('x' * 129))

    def test_rebuild_yara_rule(self):
        with data_dir.joinpath('rebuild_ruleset.yar').open('r', encoding='utf-8') as fh:
            inputString = fh.read()
        with data_dir.joinpath('rebuild_ruleset_good_enough.yar').open('r', encoding='utf-8') as fh:
            test_result = fh.read()

        result = Plyara().parse_string(inputString)

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
        self.assertEqual(detect_dependencies(result[11]), ['is__osx'])
        self.assertEqual(detect_dependencies(result[12]), list())
        self.assertEqual(detect_dependencies(result[13]), list())
        self.assertEqual(detect_dependencies(result[14]), ['is__osx'])
        self.assertEqual(detect_dependencies(result[15]), ['is__osx'])
        self.assertEqual(detect_dependencies(result[17]), ['WINDOWS_UPDATE_BDC'])

    def test_detect_imports(self):
        for imp in ('androguard', 'cuckoo', 'dotnet', 'elf', 'hash', 'magic', 'math', 'pe'):
            with data_dir.joinpath('import_ruleset_{}.yar'.format(imp)).open('r') as fh:
                inputString = fh.read()
            results = Plyara().parse_string(inputString)
            for rule in results:
                self.assertEqual(detect_imports(rule), [imp])


if __name__ == '__main__':
    unittest.main()