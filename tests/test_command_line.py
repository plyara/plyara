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
"""Unit tests for plyara command line functionality."""
import contextlib
import hashlib
import importlib.resources
import io
import os
import pathlib
import tempfile
import unittest
import unittest.mock

import plyara.command_line


class TestCLI(unittest.TestCase):
    """Checks command line scripts."""

    def setUp(self):
        data = importlib.resources.files('tests.data.command_line').joinpath('test_file.yar').read_text()
        self.td = tempfile.TemporaryDirectory()
        os.chdir(self.td.name)
        self.target = pathlib.Path(self.td.name).joinpath('test_file.yar').write_text(data)

        self.output_hashes = [
            '9d1991858f1b48b2485a9cb45692bc33c5228fb5acfa877a0d097b1db60052e3',
            '18569226a33c2f8f0c43dd0e034a6c05ea38f569adc3ca37d3c975be0d654f06',
            'b9b64df222a91d5b99b0099320134e3aecd532513965d1cf7b5a0b58881bcccc'
        ]
        self.error_hash = '15cca23e71c5307424bb71830627de444ad382479cf0c7818d65395c87770580'

    @unittest.mock.patch('argparse._sys.argv', ['plyara', 'test_file.yar'])
    def test_plyara_cli_nolog(self):
        """Check that the output hash of CLI output matches the expected hash without logging."""
        with contextlib.redirect_stdout(io.StringIO()) as out:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                plyara.command_line.main()

        output = out.getvalue()
        error = err.getvalue()
        output_hash = hashlib.sha256(output.encode()).hexdigest()

        self.assertTrue(output_hash in self.output_hashes)
        self.assertEqual(error, str())

    @unittest.mock.patch('argparse._sys.argv', ['plyara', '--log', 'test_file.yar'])
    def test_plyara_cli_withlog(self):
        """Check that the output hash of CLI output matches the expected hash with logging."""
        with contextlib.redirect_stdout(io.StringIO()) as out:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                plyara.command_line.main()

        output = out.getvalue()
        output_hash = hashlib.sha256(output.encode()).hexdigest()
        error = err.getvalue()
        error_hash = hashlib.sha256(error.encode()).hexdigest()

        self.assertTrue(output_hash in self.output_hashes)
        self.assertEqual(error_hash, self.error_hash)

    @unittest.mock.patch('argparse._sys.argv', ['plyara', 'doesnotexist.yar'])
    def test_plyara_cli_filenotfound(self):
        """Check that the error output is correct for a file not found exception."""
        with self.assertRaisesRegex(SystemExit, r"\[Errno 2\] No such file or directory: 'doesnotexist\.yar'"):
            plyara.command_line.main()

    def tearDown(self):
        """Cleanup the temporary directory."""
        self.td.cleanup()


if __name__ == '__main__':
    unittest.main()
