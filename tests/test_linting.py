# Copyright 2020 plyara Maintainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License atlinter
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
import subprocess
import unittest

import pycodestyle


class BaseTest(unittest.TestCase):
    """Bass class for all unit tests that check files in package directories."""

    def setUp(self):
        """Initialize the test fixture."""
        self.style = pycodestyle.StyleGuide(max_line_length=120)

        # Find the current working directory and set path object to package directory.
        cwd = pathlib.Path().cwd()
        if cwd.name == 'tests':
            self.package_dir = cwd.parent
        elif cwd.name == 'plyara':
            self.package_dir = cwd
        else:
            raise FileNotFoundError('Unable to locate package directory')


class TestCodeStyle(BaseTest):
    """Test formatting of code using pycodestyle linter."""

    def test_tests_conformance(self):
        """Test that unit test code conforms to PEP-8."""
        result = self.style.check_files(self.package_dir.joinpath('tests').glob('*.py'))

        self.assertEqual(result.total_errors, 0, 'Found code style errors (and warnings).')

    def test_plyara_conformance(self):
        """Test that plyara code conforms to PEP-8."""
        self.assertEqual(self.style.input_dir(str(self.package_dir.joinpath('plyara'))),
                         None, 'Found code style errors (and warnings).')


class TestDocStyle(BaseTest):
    """Test documentation string style."""

    def test_tests_docstrings(self):
        """Test that unit test docstrings conforms to PEP-257."""
        for file in self.package_dir.joinpath('tests').glob('*.py'):
            if file.name == '__init__.py':
                process = subprocess.run(['pydocstyle', '--ignore=D104', file], capture_output=True)
            else:
                process = subprocess.run(['pydocstyle', file], capture_output=True)

            self.assertFalse(process.returncode, process.stdout)

    def test_plyara_docstrings(self):
        """Test that plyara docstrings conforms to PEP-257."""
        # Only checks in the first directory. If submodules added, add a new check for that directory.
        for file in self.package_dir.joinpath('plyara').glob('*.py'):
            if file.name == '__init__.py':
                process = subprocess.run(['pydocstyle', '--ignore=D104', file], capture_output=True)
            else:
                process = subprocess.run(['pydocstyle', file], capture_output=True)

            self.assertFalse(process.returncode, process.stdout)


class TestPyflakes(BaseTest):
    """Test pyflakes."""

    def test_tests_pyflakes(self):
        """Test unit test pyflakes."""
        for file in self.package_dir.joinpath('tests').glob('*.py'):
            process = subprocess.run(['pyflakes', file], capture_output=True)

            self.assertFalse(process.returncode, process.stdout)

    def test_plyara_pyflakes(self):
        """Test plyara pyflakes."""
        # Only checks in the first directory. If submodules added, add a new check for that directory.
        for file in self.package_dir.joinpath('plyara').glob('*.py'):
            process = subprocess.run(['pyflakes', file], capture_output=True)

            self.assertFalse(process.returncode, process.stdout)


if __name__ == '__main__':
    unittest.main(exit=False, verbosity=2)
