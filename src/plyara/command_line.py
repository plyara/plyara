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
"""plyara command line script.

This module contains command line script for parsing rules.
"""
import argparse
import json
import logging
import pathlib
import sys

import plyara.core


def _set_logging():
    """Set the console logger."""
    logger = logging.getLogger('plyara')
    logger.setLevel(logging.DEBUG)
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG)
    logger.addHandler(sh)


def main():
    """Run the command line process to parse a yara rule file and output pretty printed JSON."""
    parser = argparse.ArgumentParser(description='Parse YARA rules into a JSON representation.')
    parser.add_argument('file', metavar='FILE', help='File containing YARA rules to parse.')
    parser.add_argument('--log', help='Enable debug logging to the console.', action='store_true')

    args = parser.parse_args()

    try:
        input_string = pathlib.Path(args.file).read_text(encoding='utf-8')
    except FileNotFoundError as e:
        sys.exit(e)

    parser = plyara.core.Plyara()

    if args.log:
        _set_logging()

    rules = parser.parse_string(input_string)

    print(json.dumps(rules, sort_keys=True, indent=4))
