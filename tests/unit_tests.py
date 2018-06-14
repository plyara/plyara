# coding=utf-8
import ast
import os
import subprocess
import sys
import unittest

from plyara import Plyara

UNHANDLED_RULE_MSG = "Unhandled Test Rule: {}"

class TestStaticMethods(unittest.TestCase):

    def test_logic_hash_generator(self):
        with open('tests/data/logic_collision_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = Plyara().parse_string(inputString)

        rule_mapping = {}

        for entry in result:
            rulename = entry['rule_name']
            setname, _ = rulename.split('_')
            rulehash = Plyara.generate_logic_hash(entry)

            if setname not in rule_mapping:
                rule_mapping[setname] = [rulehash]
            else:
                rule_mapping[setname].append(rulehash)

        for setname, hashvalues in rule_mapping.items():

            if not len(set(hashvalues)) == 1:
                raise AssertionError("Collision detection failure for {}".format(setname))


class TestRuleParser(unittest.TestCase):

    def setUp(self):
        self.parser = Plyara()

    def test_import_pe(self):
        with open('tests/data/import_ruleset_pe.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('pe' in rule['imports'])

    def test_import_elf(self):
        with open('tests/data/import_ruleset_elf.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('elf' in rule['imports'])

    def test_import_cuckoo(self):
        with open('tests/data/import_ruleset_cuckoo.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('cuckoo' in rule['imports'])

    def test_import_magic(self):
        with open('tests/data/import_ruleset_magic.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('magic' in rule['imports'])

    def test_import_hash(self):
        with open('tests/data/import_ruleset_hash.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('hash' in rule['imports'])

    def test_import_math(self):
        with open('tests/data/import_ruleset_math.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('math' in rule['imports'])

    def test_import_dotnet(self):
        with open('tests/data/import_ruleset_dotnet.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('dotnet' in rule['imports'])

    def test_import_androguard(self):
        with open('tests/data/import_ruleset_androguard.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for rule in result:
            self.assertTrue('androguard' in rule['imports'])

    def test_scopes(self):
        with open('tests/data/scope_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == "GlobalScope":
                self.assertTrue('global' in entry['scopes'])

            elif rulename == "PrivateScope":
                self.assertTrue('private' in entry['scopes'])

            elif rulename == "PrivateGlobalScope":
                self.assertTrue('global' in entry['scopes'] and
                                'private' in entry['scopes'])
            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))

    def test_tags(self):
        with open('tests/data/tag_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == "OneTag":
                self.assertTrue(len(entry['tags']) == 1 and
                                'tag1' in entry['tags'])

            elif rulename == "TwoTags":
                self.assertTrue(len(entry['tags']) == 2 and
                                'tag1' in entry['tags'] and
                                'tag2' in entry['tags'])

            elif rulename == "ThreeTags":
                self.assertTrue(len(entry['tags']) == 3 and
                                'tag1' in entry['tags'] and
                                'tag2' in entry['tags'] and
                                'tag3' in entry['tags'])

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))

    def test_metadata(self):
        with open('tests/data/metadata_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == "StringTypeMetadata":
                self.assertTrue('string_value' in entry['metadata'] and
                                entry['metadata']['string_value'] == 'String Metadata')

            elif rulename == "IntegerTypeMetadata":
                self.assertTrue('integer_value' in entry['metadata'] and
                                entry['metadata']['integer_value'] == '100')

            elif rulename == "BooleanTypeMetadata":
                self.assertTrue('boolean_value' in entry['metadata'] and
                                entry['metadata']['boolean_value'] == 'true')

            elif rulename == "AllTypesMetadata":
                self.assertTrue('string_value' in entry['metadata'] and
                                'integer_value' in entry['metadata'] and
                                'boolean_value' in entry['metadata'] and
                                entry['metadata']['string_value'] == 'Different String Metadata' and
                                entry['metadata']['integer_value'] == '33' and
                                entry['metadata']['boolean_value'] == 'false')

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))

    def test_strings(self):
        with open('tests/data/string_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = self.parser.parse_string(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == "Text":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$text_string', '\"foobar\"')])

            elif rulename == "FullwordText":
                self.assertTrue([(s['name'], s['value'], s['modifiers'])
                                for s in entry['strings']] ==
                                [('$text_string', '\"foobar\"', ['fullword'])])

            elif rulename == "CaseInsensitiveText":
                self.assertTrue([(s['name'], s['value'], s['modifiers'])
                                for s in entry['strings']] ==
                                [('$text_string', '\"foobar\"', ['nocase'])])

            elif rulename == "WideCharText":
                self.assertTrue([(s['name'], s['value'], s['modifiers'])
                                for s in entry['strings']] ==
                                [('$wide_string', '\"Borland\"', ['wide'])])

            elif rulename == "WideCharAsciiText":
                self.assertTrue([(s['name'], s['value'], s['modifiers'])
                                for s in entry['strings']] ==
                                [('$wide_and_ascii_string', '\"Borland\"', ['wide', 'ascii'])])

            elif rulename == "HexWildcard":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$hex_string', '{ E2 34 ?? C8 A? FB }')])

            elif rulename == "HexJump":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$hex_string', '{ F4 23 [4-6] 62 B4 }')])

            elif rulename == "HexAlternatives":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$hex_string', '{ F4 23 ( 62 B4 | 56 ) 45 }')])

            elif rulename == "HexMultipleAlternatives":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$hex_string', '{ F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }')])

            elif rulename == "RegExp":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$re1', '/md5: [0-9a-fA-F]{32}/'),
                                 ('$re2', '/state: (on|off)/')])

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rulename))


class TestYaraRules(unittest.TestCase):

    _PLYARA_SCRIPT_NAME = "plyara.py"

    def test_multiple_rules(self):
        inputString = u'''
        rule FirstRule {
            meta:
                author = "Andrés Iniesta"
                date = "2015-01-01"
            strings:
                $a = "hark, a \\"string\\" here" fullword ascii
                $b = { 00 22 44 66 88 aa cc ee }
            condition:
                all of them
            }

        import "bingo"
        import "bango"
        rule SecondRule : aTag {
            meta:
                author = "Ivan Rakitić"
                date = "2015-02-01"
            strings:
                $x = "hi"
                $y = /state: (on|off)/ wide
                $z = "bye"
            condition:
                for all of them : ( # > 2 )
        }

        rule ThirdRule {condition: uint32(0) == 0xE011CFD0}
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputString)

        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]['metadata']['author'], u'Andrés Iniesta')
        self.assertEqual(result[0]['metadata']['date'], '2015-01-01')
        self.assertTrue([x["name"] for x in result[0]['strings']] == ['$a', '$b'])

    def disable_test_rule_name_imports_and_scopes(self):
        inputStringNIS = r'''
        rule four {meta: i = "j" strings: $a = "b" condition: true }

        global rule five {meta: i = "j" strings: $a = "b" condition: false }

        private rule six {meta: i = "j" strings: $a = "b" condition: true }

        global private rule seven {meta: i = "j" strings: $a = "b" condition: true }

        import "lib1"
        rule eight {meta: i = "j" strings: $a = "b" condition: true }

        import "lib1"
        import "lib2"
        rule nine {meta: i = "j" strings: $a = "b" condition: true }

        import "lib2"
        private global rule ten {meta: i = "j" strings: $a = "b" condition: true }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputStringNIS)

        self.assertEqual(len(result), 7)

        for rule in result:
            rule_name = rule["rule_name"]

            if rule_name == 'four':
                self.assertTrue('scopes' not in rule)
                self.assertTrue('imports' in rule)
            if rule_name == 'five':
                self.assertTrue('imports' in rule)
                self.assertTrue('global' in rule['scopes'])
            if rule_name == 'six':
                self.assertTrue('imports' in rule)
                self.assertTrue('private' in rule['scopes'])
            if rule_name == 'seven':
                self.assertTrue('imports' in rule)
                self.assertTrue('private' in rule['scopes'] and 'global' in rule['scopes'])
            if rule_name == 'eight':
                self.assertTrue('lib1' in rule['imports'])
                self.assertTrue('scopes' not in rule)
            if rule_name == 'nine':
                self.assertTrue('lib1' in rule['imports'] and 'lib2' in rule['imports'])
                self.assertTrue('scopes' not in rule)
            if rule_name == 'ten':
                self.assertTrue('lib1' in rule['imports'] and 'lib2' in rule['imports'])
                self.assertTrue('global' in rule['scopes'] and 'private' in rule['scopes'])

    def test_rule_name_imports_by_instance(self):
        input1 = r'''
        rule one {meta: i = "j" strings: $a = "b" condition: true }

        '''
        input2 = r'''
        import "lib1"
        rule two {meta: i = "j" strings: $a = "b" condition: true }

        import "lib2"
        private global rule three {meta: i = "j" strings: $a = "b" condition: true }
        '''

        plyara1 = Plyara()
        result1 = plyara1.parse_string(input1)

        plyara2 = Plyara()
        result2 = plyara2.parse_string(input2)

        self.assertEqual(len(result1), 1)
        self.assertEqual(len(result2), 2)

        for rule in result1:
            rule_name = rule["rule_name"]

            if rule_name == 'one':
                self.assertTrue('scopes' not in rule)
                self.assertTrue('imports' not in rule)

        for rule in result2:
            rule_name = rule["rule_name"]

            if rule_name == 'two':
                self.assertTrue('lib1' in rule['imports'] and 'lib2' in rule['imports'])
                self.assertTrue('scopes' not in rule)
            if rule_name == 'three':
                self.assertTrue('lib1' in rule['imports'] and 'lib2' in rule['imports'])
                self.assertTrue('global' in rule['scopes'] and 'private' in rule['scopes'])

    def test_rule_name(self):
        inputRule = r'''
        rule testName
        {
        meta:
        my_identifier_1 = ""
        my_identifier_2 = 24
        my_identifier_3 = true

        strings:
                $my_text_string = "text here"
                $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
                $my_text_string or $my_hex_string
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRule)

        self.assertTrue(len(result) == 1)
        self.assertTrue(result[0]['rule_name'] == "testName")

    def test_store_raw(self):
        inputRule = r'''
        rule testName
        {
        meta:
            my_identifier_1 = ""
            my_identifier_2 = 24
            my_identifier_3 = true

        strings:
            $my_text_string = "text here"
            $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
            $my_text_string or $my_hex_string
        }

        rule testName2 {
        strings:
            $test1 = "some string"

        condition:
            $test1 or true
        }

        rule testName3 {

        condition:
            true
        }

        rule testName4 : tag1 tag2 {meta: i = "j" strings: $a = "b" condition: true }
        '''

        plyara = Plyara(store_raw_sections=True)
        result = plyara.parse_string(inputRule)

        self.assertTrue(len(result) == 4)
        self.assertTrue(result[0].get("raw_meta", False))
        self.assertTrue(result[0].get("raw_strings", False))
        self.assertTrue(result[0].get("raw_condition", False))

        self.assertFalse(result[1].get("raw_meta", False))
        self.assertTrue(result[1].get("raw_strings", False))
        self.assertTrue(result[1].get("raw_condition", False))

        self.assertFalse(result[2].get("raw_meta", False))
        self.assertFalse(result[2].get("raw_strings", False))
        self.assertTrue(result[2].get("raw_condition", False))

        self.assertTrue(result[3].get("raw_meta", False))
        self.assertTrue(result[3].get("raw_strings", False))
        self.assertTrue(result[3].get("raw_condition", False))

    def test_tags(self):
        inputTags = r'''
        rule eleven: tag1 {meta: i = "j" strings: $a = "b" condition: true }

        rule twelve : tag1 tag2 {meta: i = "j" strings: $a = "b" condition: true }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputTags)

        for rule in result:
            rule_name = rule["rule_name"]
            if rule_name == 'eleven':
                self.assertTrue(len(rule['tags']) == 1 and 'tag1' in rule['tags'])
            if rule_name == 'twelve':
                self.assertTrue(len(rule['tags']) == 2 and
                        'tag1' in rule['tags'] and 'tag2' in rule['tags'])

    def test_empty_string(self):
        inputRules = r'''
        rule thirteen
        {
        meta:
            my_identifier_1 = ""
            my_identifier_2 = 24
            my_identifier_3 = true

        strings:
            $my_text_string = "text here"
            $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
            $my_text_string or $my_hex_string
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        for rule in result:
            rule_name = rule["rule_name"]
            if rule_name == 'thirteen':
                self.assertTrue(len(rule['metadata']) == 3)

    def test_bytestring(self):
        inputRules = r'''
        rule testName
        {
        strings:
            $a1 = { E2 34 A1 C8 23 FB }
            $a2 = { E2 34 A1 C8 2? FB }
            $a3 = { E2 34 A1 C8 ?? FB }
            $a4 = { E2 34 A1 [6] FB }
            $a5 = { E2 34 A1 [4-6] FB }
            $a6 = { E2 34 A1 [4 - 6] FB }
            $a7 = { E2 34 A1 [-] FB }
            $a8 = { E2 34 A1 [10-] FB }
            $a9 = { E2 23 ( 62 B4 | 56 ) 45 }

        condition:
            any of them
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(len(result), 1)
        for rule in result:
            rule_name = rule["rule_name"]
            if rule_name == 'testName':
                self.assertEqual(len(rule['strings']), 9)
                for hex_string in rule['strings']:
                    # Basic sanity check.
                    self.assertTrue(hex_string['value'].startswith('{ E2'))

    def test_rexstring(self):
        inputRules = r'''
        rule testName
        {
        strings:
            $a1 = /abc123 \d/i
            $a2 = /abc123 \d+/i // comment
            $a3 = /abc123 \d\/ afterspace/im // comment
            $a4 = /abc123 \d\/ afterspace/im nocase // comment

            /* It should only consume the regex pattern and not text modifiers
               or comment, as those will be parsed separately. */

        condition:
            any of them
        }
        '''

        plyara = Plyara()
        result = plyara.parse_string(inputRules)

        self.assertEqual(len(result), 1)
        for rule in result:
            rule_name = rule["rule_name"]
            if rule_name == 'testName':
                self.assertEqual(len(rule['strings']), 4)
                for rex_string in rule['strings']:
                    if rex_string['name'] == '$a1':
                        self.assertEqual(rex_string['value'], '/abc123 \\d/i')
                    elif rex_string['name'] == '$a2':
                        self.assertEqual(rex_string['value'], '/abc123 \\d+/i')
                    elif rex_string['name'] == '$a3':
                        self.assertEqual(rex_string['value'], '/abc123 \\d\\/ afterspace/im')
                    elif rex_string['name'] == '$a4':
                        self.assertEqual(rex_string['value'], '/abc123 \\d\\/ afterspace/im')
                        self.assertEqual(rex_string['modifiers'], ['nocase'])
                    else:
                        self.assertFalse("Unknown rule name...")

    def test_plyara_script(self):
        cwd = os.getcwd()
        script_path = os.path.join(cwd, self._PLYARA_SCRIPT_NAME)
        test_file_path = os.path.join(cwd, 'tests', 'data', 'test_file.txt')

        script_process = subprocess.Popen([sys.executable, script_path, test_file_path],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        process_stdout, process_stderr = script_process.communicate()
        rule_list = ast.literal_eval(process_stdout.decode('utf-8'))
        self.assertTrue(len(rule_list) == 4)


if __name__ == '__main__':
    unittest.main()
