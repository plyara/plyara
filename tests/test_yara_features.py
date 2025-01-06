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
"""Unit tests for specific language features in YARA."""
import importlib.resources
import unittest

import plyara.core


class TestImports(unittest.TestCase):
    """Check parsing of import statements."""

    def setUp(self):
        self.parser = plyara.core.Plyara()
        self.data = importlib.resources.files('tests.data.yara_features.imports')

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


if __name__ == '__main__':
    unittest.main()
