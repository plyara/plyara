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
"""Unit tests for plyara Github issue fixes."""
import pathlib
import unittest

from plyara.core import Plyara
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
        rules = list()
        plyara = Plyara()

        for file in DATA_DIR.glob('issue99*.yar'):
            with open(file, 'r') as fh:
                yararules = plyara.parse_string(fh.read())
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


if __name__ == '__main__':
    unittest.main()
