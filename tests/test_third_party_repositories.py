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
"""Test plyara against rule repositories."""
import subprocess
import unittest

from pathlib import Path
from tempfile import TemporaryDirectory

from plyara.core import Plyara


class TestPublicYaraRules(unittest.TestCase):
    """Check parsing of third-party YARA rules."""

    def test_third_party_rules(self):
        # Perform testing against a set of public YARA rule repositories to assess parsing capability
        projects = [
            # "AlienVault-Labs/AlienVaultLabs", issue: https://github.com/plyara/plyara/issues/155
            "bartblaze/Yara-rules",
            "The-DFIR-Report/Yara-Rules",
            "ditekshen/detection",
            "elastic/protections-artifacts",
            "eset/malware-ioc",
            "Neo23x0/signature-base",
            "intezer/yara-rules",
            "JPCERTCC/jpcert-yara",
            "malpedia/signator-rules",
            "kevoreilly/CAPE",
            "reversinglabs/reversinglabs-yara-rules",
            "stratosphereips/yara-rules",
            "advanced-threat-research/Yara-Rules",
            "volexity/threat-intel",
        ]
        for project in projects:
            with TemporaryDirectory() as rules_directory:
                # Fetch the most recent commit from project for testing
                subprocess.run(
                    [
                        "git",
                        "clone",
                        "--depth",
                        "1",
                        f"https://github.com/{project}.git",
                    ],
                    cwd=rules_directory,
                    capture_output=True
                )

                # Traverse the project in search of YARA rules to test with
                for yara_file in Path(rules_directory).rglob("*.yar*"):
                    if ".yar" in yara_file.suffix:
                        with self.subTest(msg=project, yara_file=yara_file):
                            # Check to see if we run into a parsing error
                            plyara = Plyara()
                            plyara.parse_string(yara_file.read_text())
