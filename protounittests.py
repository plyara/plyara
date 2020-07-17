"""Unit test prototypes."""
from plyara.model import Statements, Rule, Meta, MetaDeclaration, Condition, Boolean
from plyara.to_yara import to_yara

rule1 = """rule test
{
    condition:
        true
}
"""

model1 = Statements([
                    Rule('test', None, None, None, None, None, Condition([
                                                                         Boolean(True)
                                                                         ]))
                    ])

print(model1)
print(rule1)
print(to_yara(model1))

print(rule1 == to_yara(model1))

rule2 = """rule test
{
    meta:
        description = "This is a YARA rule."
    condition:
        false
}
"""

model2 = Statements([
                    Rule('test', None, None, None, Meta([
                                                        MetaDeclaration('description', 'string', 'This is a YARA rule.')
                                                        ]), None, Condition([
                                                                            Boolean(False)
                                                                            ]))
                    ])

print(model2)
print(rule2)
print(to_yara(model2))

print(rule2 == to_yara(model2))
