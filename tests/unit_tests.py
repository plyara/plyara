import unittest
import interp.interp as interp

#todo - get rid of this
import pprint

class TestYaraRules(unittest.TestCase):

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
    rule SecondRule {
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

    rule ThirdRule {condition: false}
    '''

    result = interp.parseString(inputString, isPrintDebug=True)
    #Assert two rules are derived.
    self.assertEqual(len(result), 3)

    self.assertEqual(result[0]['metadata']['author'], '"Andrés Iniesta"')
    self.assertEqual(result[0]['metadata']['date'], '"2015-01-01"')
    self.assertTrue([x["name"] for x in result[0]['strings']] == ['$a','$b'])

    #todo - get rid of this
    pp = pprint.PrettyPrinter(indent=2)
    pp.pprint(result)

  def test_rule_name_imports_and_scopes(self):

    inputStringNIS = r'''

    rule four {meta: i = "j" strings: $a = "b" condition: true }

    global rule five {meta: i = "j" strings: $a = "b" condition: true }

    private rule six {meta: i = "j" strings: $a = "b" condition: true }

    global private rule seven {meta: i = "j" strings: $a = "b" condition: true }

    import "lib1"
    rule eight {meta: i = "j" strings: $a = "b" condition: true }

    import "lib1"
    import "lib2"
    rule nine {meta: i = "j" strings: $a = "b" condition: true }

    import "lib1"
    import "lib2"
    private global rule ten {meta: i = "j" strings: $a = "b" condition: true }


    '''

    result = interp.parseString(inputStringNIS, isPrintDebug=True)

    #todo - get rid of this
    print("------")
    pp = pprint.PrettyPrinter(indent=2)
    pp.pprint(result)


    self.assertEqual(len(result), 10)

    for rule in result:
      rule_name = rule["rule_name"]
      if rule_name== 'four':
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



if __name__ == '__main__':
    unittest.main()