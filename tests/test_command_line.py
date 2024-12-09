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
"""Unit tests for plyara command line functionality."""
import contextlib
import hashlib
import io
import pathlib
import sys
import unittest

from plyara.command_line import main

DATA_DIR = pathlib.Path(__file__).parent.joinpath('data')


@contextlib.contextmanager
def captured_output():
    """Capture stdout and stderr from execution."""
    new_out, new_err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestCLI(unittest.TestCase):
    """Checks command line scripts."""

    def test_plyara_script(self):
        """Check that the output hash of CLI output matches the expected hash."""
        test_file_path = DATA_DIR.joinpath('test_file.txt')

        # Without logging
        with captured_output() as (out, err):
            main([str(test_file_path)])
            output = out.getvalue()
            error = err.getvalue()
        output_hash = hashlib.sha256(output.encode()).hexdigest()

        self.assertTrue(output_hash in ['9d1991858f1b48b2485a9cb45692bc33c5228fb5acfa877a0d097b1db60052e3',
                                        '18569226a33c2f8f0c43dd0e034a6c05ea38f569adc3ca37d3c975be0d654f06',
                                        'b9b64df222a91d5b99b0099320134e3aecd532513965d1cf7b5a0b58881bcccc'])
        self.assertEqual(error, str())

        # With logging
        with captured_output() as (out, err):
            main(['--log', str(test_file_path)])
            output = out.getvalue()
            error = err.getvalue()
        output_hash = hashlib.sha256(output.encode()).hexdigest()
        error_hash = hashlib.sha256(error.encode()).hexdigest()

        self.assertTrue(output_hash in ['9d1991858f1b48b2485a9cb45692bc33c5228fb5acfa877a0d097b1db60052e3',
                                        '18569226a33c2f8f0c43dd0e034a6c05ea38f569adc3ca37d3c975be0d654f06',
                                        'b9b64df222a91d5b99b0099320134e3aecd532513965d1cf7b5a0b58881bcccc'])
        self.assertTrue(error_hash in ['4c303175e30f2257cc11ede86e08329815d2c06ada198e32055f0c88b73dda5a'])


if __name__ == '__main__':
    unittest.main()
