"""Unit test prototypes."""
from plyara.model import Statements, Rule, RuleTypes, RuleType, Tags, Tag, Meta, MetaDefinition
from plyara.model import Strings, StrDefinition, Modifiers, Modifier, Alphabet, Range, Condition
from plyara.model import Boolean, Variable
from plyara.export import to_yara

rule1 = """rule test
{
    condition:
        true
}
"""

model1 = Statements([
                    Rule('test', None, None, None, None, Condition([
                                                                   Boolean(True)
                                                                   ]))
                    ])

print(model1)
print(rule1)
print(to_yara(model1))

print(rule1 == to_yara(model1))

rule2_1 = """rule test
{
    meta:
        description = "This is a YARA rule."
    condition:
        false
}
"""

model2_1 = Statements([
                      Rule('test', None, None, Meta([
                                                    MetaDefinition('description', 'string', 'This is a YARA rule.')
                                                    ]), None, Condition([
                                                                        Boolean(False)
                                                                        ]))
                      ])

print(model2_1)
print(rule2_1)
print(to_yara(model2_1))

print(rule2_1 == to_yara(model2_1))

rule2_2 = """rule test
{
    meta:
        description = "This is a YARA rule."
        threat_level = 5
    condition:
        false
}
"""

model2_2 = Statements([
                      Rule('test', None, None, Meta([
                                                    MetaDefinition('description', 'string', 'This is a YARA rule.'),
                                                    MetaDefinition('threat_level', 'number', 5)
                                                    ]), None, Condition([
                                                                        Boolean(False)
                                                                        ]))
                      ])

print(model2_2)
print(rule2_2)
print(to_yara(model2_2))

print(rule2_2 == to_yara(model2_2))

rule2_3 = """rule test
{
    meta:
        description = "This is a YARA rule."
        threat_level = 5
        in_the_wild = false
    condition:
        false
}
"""

model2_3 = Statements([
                      Rule('test', None, None, Meta([
                                                    MetaDefinition('description', 'string', 'This is a YARA rule.'),
                                                    MetaDefinition('threat_level', 'number', 5),
                                                    MetaDefinition('in_the_wild', 'boolean', False)
                                                    ]), None, Condition([
                                                                        Boolean(False)
                                                                        ]))
                      ])

print(model2_3)
print(rule2_3)
print(to_yara(model2_3))

print(rule2_3 == to_yara(model2_3))

rule3 = """private rule test
{
    meta:
        description = "This is a YARA rule."
    condition:
        false
}
"""

model3 = Statements([
                    Rule('test', RuleTypes([
                                           RuleType('private')
                                           ]), None, Meta([
                                                          MetaDefinition('description', 'string', 'This is a YARA rule.')
                                                          ]), None, Condition([
                                                                              Boolean(False)
                                                                              ]))
                    ])

print(model3)
print(rule3)
print(to_yara(model3))

print(rule3 == to_yara(model3))

rule4 = """global rule test
{
    meta:
        description = "This is a YARA rule."
    condition:
        false
}
"""

model4 = Statements([
                    Rule('test', RuleTypes([
                                           RuleType('global')
                                           ]), None, Meta([
                                                          MetaDefinition('description', 'string', 'This is a YARA rule.')
                                                          ]), None, Condition([
                                                                              Boolean(False)
                                                                              ]))
                    ])

print(model4)
print(rule4)
print(to_yara(model4))

print(rule4 == to_yara(model4))

rule5 = """private global rule test
{
    meta:
        description = "This is a YARA rule."
    condition:
        false
}
"""

model5 = Statements([
                    Rule('test', RuleTypes([
                                           RuleType('private'),
                                           RuleType('global'),
                                           ]), None, Meta([
                                                          MetaDefinition('description', 'string', 'This is a YARA rule.')
                                                          ]), None, Condition([
                                                                              Boolean(False)
                                                                              ]))
                    ])

print(model5)
print(rule5)
print(to_yara(model5))

print(rule5 == to_yara(model5))

rule6 = """global private rule test
{
    meta:
        description = "This is a YARA rule."
    condition:
        false
}
"""

model6 = Statements([
                    Rule('test', RuleTypes([
                                           RuleType('global'),
                                           RuleType('private'),
                                           ]), None, Meta([
                                                          MetaDefinition('description', 'string', 'This is a YARA rule.')
                                                          ]), None, Condition([
                                                                              Boolean(False)
                                                                              ]))
                    ])

print(model6)
print(rule6)
print(to_yara(model6))

print(rule6 == to_yara(model6))

rule7 = """rule test : OneTag
{
    meta:
        description = "This is a YARA rule."
    condition:
        false
}
"""

model7 = Statements([
                    Rule('test', None, Tags([
                                            Tag('OneTag')
                                            ]), Meta([
                                                     MetaDefinition('description', 'string', 'This is a YARA rule.')
                                                     ]), None, Condition([
                                                                         Boolean(False)
                                                                         ]))
                    ])

print(model7)
print(rule7)
print(to_yara(model7))

print(rule7 == to_yara(model7))

rule8 = """rule test : OneTag TwoTag
{
    meta:
        description = "This is a YARA rule."
    condition:
        false
}
"""

model8 = Statements([
                    Rule('test', None, Tags([
                                            Tag('OneTag'),
                                            Tag('TwoTag')
                                            ]), Meta([
                                                     MetaDefinition('description', 'string', 'This is a YARA rule.')
                                                     ]), None, Condition([
                                                                         Boolean(False)
                                                                         ]))
                    ])

print(model8)
print(rule8)
print(to_yara(model8))

print(rule8 == to_yara(model8))

rule9 = """rule test
{
    meta:
        description = "This is a YARA rule."
        threat_level = 5
        in_the_wild = false
    strings:
        $a = "dummy1"
    condition:
        $a
}
"""

model9 = Statements([
                    Rule('test', None, None, Meta([
                                                  MetaDefinition('description', 'string', 'This is a YARA rule.'),
                                                  MetaDefinition('threat_level', 'number', 5),
                                                  MetaDefinition('in_the_wild', 'boolean', False)
                                                  ]), Strings([
                                                              StrDefinition('a', 'text', 'dummy1', None)
                                                              ]), Condition([
                                                                            Variable('a', 'variable')
                                                                            ]))
                    ])

print(model9)
print(rule9)
print(to_yara(model9))

print(rule9 == to_yara(model9))

rule10 = """rule test
{
    meta:
        description = "This is a YARA rule."
        threat_level = 5
        in_the_wild = false
    strings:
        $a = { 4D 5A }
    condition:
        $a
}
"""

model10 = Statements([
                     Rule('test', None, None, Meta([
                                                   MetaDefinition('description', 'string', 'This is a YARA rule.'),
                                                   MetaDefinition('threat_level', 'number', 5),
                                                   MetaDefinition('in_the_wild', 'boolean', False)
                                                   ]), Strings([
                                                               StrDefinition('a', 'hex', '4D 5A', None)
                                                               ]), Condition([
                                                                             Variable('a', 'variable')
                                                                             ]))
                     ])

print(model10)
print(rule10)
print(to_yara(model10))

print(rule10 == to_yara(model10))

rule11 = """rule test
{
    meta:
        description = "This is a YARA rule."
        threat_level = 5
        in_the_wild = false
    strings:
        $a = /md5: [0-9a-fA-F]{32}/
    condition:
        $a
}
"""

model11 = Statements([
                     Rule('test', None, None, Meta([
                                                   MetaDefinition('description', 'string', 'This is a YARA rule.'),
                                                   MetaDefinition('threat_level', 'number', 5),
                                                   MetaDefinition('in_the_wild', 'boolean', False)
                                                   ]), Strings([
                                                               StrDefinition('a', 'regex', 'md5: [0-9a-fA-F]{32}', None)
                                                               ]), Condition([
                                                                             Variable('a', 'variable')
                                                                             ]))
                     ])

print(model11)
print(rule11)
print(to_yara(model11))

print(rule11 == to_yara(model11))

rule12 = """rule test
{
    meta:
        description = "This is a YARA rule."
        threat_level = 5
        in_the_wild = false
    strings:
        $a = "dummy1" nocase
    condition:
        $a
}
"""

model12 = Statements([
                     Rule('test', None, None, Meta([
                                                   MetaDefinition('description', 'string', 'This is a YARA rule.'),
                                                   MetaDefinition('threat_level', 'number', 5),
                                                   MetaDefinition('in_the_wild', 'boolean', False)
                                                   ]), Strings([
                                                               StrDefinition('a', 'text', 'dummy1', Modifiers([
                                                                                                              Modifier('nocase', None)
                                                                                                              ]))
                                                               ]), Condition([
                                                                             Variable('a', 'variable')
                                                                             ]))
                     ])

print(model12)
print(rule12)
print(to_yara(model12))

print(rule12 == to_yara(model12))

modifier_keywords = ['nocase', 'wide', 'ascii', 'xor', 'base64', 'base64wide', 'fullword', 'private']

rule_template = """rule test
{{
    meta:
        description = "This is a YARA rule."
        threat_level = 5
        in_the_wild = false
    strings:
        $a = "dummy1" {}
    condition:
        $a
}}
"""

for keyword in modifier_keywords:
    base_model = Statements([
                            Rule('test', None, None, Meta([
                                                          MetaDefinition('description', 'string', 'This is a YARA rule.'),
                                                          MetaDefinition('threat_level', 'number', 5),
                                                          MetaDefinition('in_the_wild', 'boolean', False)
                                                          ]), Strings([
                                                                      StrDefinition('a', 'text', 'dummy1', Modifiers([
                                                                                                                     Modifier(keyword, None)
                                                                                                                     ]))
                                                                      ]), Condition([
                                                                                    Variable('a', 'variable')
                                                                                    ]))
                            ])

    print(base_model)
    print(rule_template.format(keyword))
    print(to_yara(base_model))

    print(f'{keyword}: ', rule_template.format(keyword) == to_yara(base_model))

rule13 = """rule test
{
    meta:
        description = "This is a YARA rule."
        threat_level = 5
        in_the_wild = false
    strings:
        $a = "dummy1" xor(0x01-0xff)
    condition:
        $a
}
"""

model13 = Statements([
                     Rule('test', None, None, Meta([
                                                   MetaDefinition('description', 'string', 'This is a YARA rule.'),
                                                   MetaDefinition('threat_level', 'number', 5),
                                                   MetaDefinition('in_the_wild', 'boolean', False)
                                                   ]), Strings([
                                                               StrDefinition('a', 'text', 'dummy1', Modifiers([
                                                                                                              Modifier('xor', Range('01', 'ff'))
                                                                                                              ]))
                                                               ]), Condition([
                                                                             Variable('a', 'variable')
                                                                             ]))
                     ])

print(model13)
print(rule13)
print(to_yara(model13))

print(rule13 == to_yara(model13))

rule14 = r"""rule test
{
    meta:
        description = "This is a YARA rule."
        threat_level = 5
        in_the_wild = false
    strings:
        $a = "dummy1" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
    condition:
        $a
}
"""

model14 = Statements([
                     Rule('test', None, None, Meta([
                                                   MetaDefinition('description', 'string', 'This is a YARA rule.'),
                                                   MetaDefinition('threat_level', 'number', 5),
                                                   MetaDefinition('in_the_wild', 'boolean', False)
                                                   ]), Strings([
                                                               StrDefinition('a', 'text', 'dummy1', Modifiers([
                                                                                                              Modifier('base64', Alphabet(r'!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu'))
                                                                                                              ]))
                                                               ]), Condition([
                                                                             Variable('a', 'variable')
                                                                             ]))
                     ])

print(model14)
print(rule14)
print(to_yara(model14))

print(rule14 == to_yara(model14))
