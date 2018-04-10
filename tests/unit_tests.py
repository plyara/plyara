# coding=utf-8
import ast
import os
import subprocess
import sys
import unittest
from plyara import Plyara


class TestYaraRules(unittest.TestCase):

  _PLYARA_SCRIPT_NAME = "plyara.py"

  def test_multiple_rules(self):

    inputString = r'''

    rule FirstRule {
      meta:
        author = "Andrés Iniesta"
        date = "2015-01-01"
      strings:
        $a = "hark, a \"string\" here" fullword ascii
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
    self.assertEqual(result[0]['metadata']['author'], 'Andrés Iniesta')
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
        self.assertTrue('imports' not in rule)
      if rule_name == 'five':
        self.assertTrue('imports' not in rule)
        self.assertTrue('global' in rule['scopes'])
      if rule_name == 'six':
        self.assertTrue('imports' not in rule)
        self.assertTrue('private' in rule['scopes'])
      if rule_name == 'seven':
        self.assertTrue('imports' not in rule)
        self.assertTrue('private' in rule['scopes'] and 'global' in rule['scopes'])
      if rule_name == 'eight':
        self.assertTrue('"lib1"' in rule['imports'])
        self.assertTrue('scopes' not in rule)
      if rule_name == 'nine':
        self.assertTrue('"lib1"' in rule['imports'] and '"lib2"' in rule['imports'])
        self.assertTrue('scopes' not in rule)
      if rule_name == 'ten':
        self.assertTrue('"lib1"' in rule['imports'] and '"lib2"' in rule['imports'])
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
        self.assertTrue('"lib1"' in rule['imports'] and '"lib2"' in rule['imports'])
        self.assertTrue('scopes' not in rule)
      if rule_name == 'three':
        self.assertTrue('"lib1"' in rule['imports'] and '"lib2"' in rule['imports'])
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

  def test_plyara_script(self):

    cwd = os.getcwd()
    base_dir = cwd[:cwd.rindex('/')]
    script_path = base_dir + "/plyara/" + self._PLYARA_SCRIPT_NAME

    script_process = subprocess.Popen([sys.executable, script_path, cwd + '/test_file.txt'],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    process_stdout, process_stderr = script_process.communicate()
    rule_list = ast.literal_eval(process_stdout.decode('utf-8'))
    self.assertTrue(len(rule_list) == 4)


if __name__ == '__main__':
    unittest.main()
