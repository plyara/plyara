"""plyara command line script.

This module contains command line script for parsing rules.
"""
import argparse
import io
import json

from plyara.core import Plyara


def main():
    """Run main function."""
    parser = argparse.ArgumentParser(description='Parse YARA rules into a dictionary representation.')
    parser.add_argument('file', metavar='FILE', help='File containing YARA rules to parse.')
    parser.add_argument('--log', help='Enable debug logging to the console.', action='store_true')
    args, _ = parser.parse_known_args()

    with io.open(args.file, 'r', encoding='utf-8') as fh:
        input_string = fh.read()

    plyara = Plyara(console_logging=args.log)
    rules = plyara.parse_string(input_string)

    # can't JSON-serialize sets, so convert them to lists at print time
    def default(obj):
        if isinstance(obj, set):
            return list(obj)
        raise TypeError

    print(json.dumps(rules, sort_keys=True, indent=4, default=default))


if __name__ == '__main__':
    main()
