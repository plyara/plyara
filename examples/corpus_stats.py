"""Example script that demonstrates using plyara."""
import argparse
import operator

import plyara


def example():
    """Execute the example code."""
    parser = argparse.ArgumentParser()
    parser.add_argument('file', metavar='FILE', help='File containing YARA rules to parse.')
    args = parser.parse_args()

    print('Parsing file...')
    with open(args.file, 'r') as fh:
        data = fh.read()

    parser = plyara.Plyara()
    rules_dict = parser.parse_string(data)
    print('Analyzing dictionary...')

    imps = {}
    tags = {}
    rule_count = 0

    for rule in rules_dict:
        rule_count += 1

        # Imports
        if 'imports' in rule:
            for imp in rule['imports']:
                imp = imp.replace('"', '')
                if imp in imps:
                    imps[imp] += 1
                else:
                    imps[imp] = 1

        # Tags
        if 'tags' in rule:
            for tag in rule['tags']:
                if tag in tags:
                    tags[tag] += 1
                else:
                    tags[tag] = 1

    print('\n======================\n')
    print('Number of rules in file: {}'.format(rule_count))

    ordered_imps = sorted(imps.items(), key=operator.itemgetter(1), reverse=True)

    ordered_tags = sorted(tags.items(), key=operator.itemgetter(1), reverse=True)

    print('\n======================\n')
    print('Top imports:')
    for i in range(5):
        if i < len(ordered_imps):
            print(ordered_imps[i])

    print('\n======================\n')
    print('Top tags:')
    for i in range(5):
        if i < len(ordered_tags):
            print(ordered_tags[i])


if __name__ == '__main__':
    example()
