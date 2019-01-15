#!/usr/bin/env python3
# Copyright 2014 Christian Buia
# Copyright 2019 plyara Maintainers
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

from plyara.core import Plyara


def main():
    """Run the command line process to parse a yara rule file and output pretty printed JSON."""
    parser = argparse.ArgumentParser(description='Parse YARA rules into a dictionary representation.')
    parser.add_argument('file', metavar='FILE', help='File containing YARA rules to parse.')
    parser.add_argument('--log', help='Enable debug logging to the console.', action='store_true')
    args = parser.parse_args()

    with open(args.file, 'r', encoding='utf-8') as fh:
        input_string = fh.read()

    plyara = Plyara(console_logging=args.log)
    rules = plyara.parse_string(input_string)

    print(json.dumps(rules, sort_keys=True, indent=4))


if __name__ == '__main__':
    main()
