# Copyright 2020 plyara Maintainers
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
"""Unit tests for code style and errors."""
import pathlib
import unittest

import pycodestyle


class TestCodeFormat(unittest.TestCase):
    """Test formatting of code using pycodestyle linter."""

    def setUp(self):
        """Setup the test fixture."""
        self.style = pycodestyle.StyleGuide(max_line_length=120)

        # Find the current working directory and set path object to package directory.
        cwd = pathlib.Path().cwd()
        if cwd.name == 'tests':
            self.package_dir = cwd.parent
        elif cwd.name == 'plyara':
            self.package_dir = cwd
        else:
            raise FileNotFoundError('Unable to locate package directory')

    def test_tests_conformance(self):
        """Test that unit test code conforms to PEP-8."""
        result = self.style.check_files(self.package_dir.joinpath('tests').glob('*.py'))

        self.assertEqual(result.total_errors, 0, 'Found code style errors (and warnings).')


if __name__ == '__main__':
    unittest.main(exit=False, verbosity=2)
