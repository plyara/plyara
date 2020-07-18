# Copyright 2020 plyara Maintainers
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
"""Functionality to export data model to YARA rules.

Takes the classes in the data model and uses single dispatch from the functools
package to implement a visitor pattern that generates YARA rules in standard
text format.
"""
from functools import singledispatch

from .model import Ruleset, Grouping, Import, Include, Rule, RuleTypes, RuleType, Tags, Tag, Meta, MetaDefinition
from .model import Strings, StrDefinition, Modifiers, Modifier, Alphabet, Range, Condition
from .model import Boolean, Variable


def to_yara(node):
    """Convert data model to valid YARA rules."""
    return _to_yara(node)


@singledispatch
def _to_yara(node):
    raise RuntimeError(f'Unrecognized node: {node}')


@_to_yara.register(Ruleset)
def _(node):
    return ''.join(_to_yara(stmt) for stmt in node.statements)


@_to_yara.register(Grouping)
def _(node):
    return '\n'.join(_to_yara(stmt) for stmt in node.statements) + '\n\n'


@_to_yara.register(Import)
def _(node):
    return f'import "{node.module}"'


@_to_yara.register(Include)
def _(node):
    return f'include "{node.path}"'


@_to_yara.register(Rule)
def _(node):
    rule_types = f'{_to_yara(node.rule_types)} ' if node.rule_types else ''
    tags = f' : {_to_yara(node.tags)}' if node.tags else ''
    meta = f'    meta:\n        {_to_yara(node.meta)}\n' if node.meta else ''
    strings = f'    strings:\n        {_to_yara(node.strings)}\n' if node.strings else ''
    condition = f'    condition:\n        {_to_yara(node.condition)}\n' if node.condition else ''

    return f'{rule_types}rule {node.identifier}{tags}\n{{\n{meta}{strings}{condition}}}\n'


@_to_yara.register(RuleTypes)
def _(node):
    return ' '.join(_to_yara(rule_type) for rule_type in node.rule_types)


@_to_yara.register(RuleType)
def _(node):
    return f'{node.value}'


@_to_yara.register(Tags)
def _(node):
    return ' '.join(_to_yara(tag) for tag in node.tags)


@_to_yara.register(Tag)
def _(node):
    return f'{node.value}'


@_to_yara.register(Meta)
def _(node):
    return '\n        '.join(_to_yara(definition) for definition in node.definitions)


@_to_yara.register(MetaDefinition)
def _(node):
    if node.type == 'string':
        return f'{node.identifier} = "{node.value}"'

    elif node.type == 'number':
        return f'{node.identifier} = {node.value}'

    elif node.type:
        if node.value:
            return f'{node.identifier} = true'
        else:
            return f'{node.identifier} = false'

    else:
        raise RuntimeError(f'Unrecognized meta type: {node.type}')


@_to_yara.register(Strings)
def _(node):
    return '\n        '.join(_to_yara(definition) for definition in node.strings)


@_to_yara.register(StrDefinition)
def _(node):
    identifier = node.identifier if node.identifier else ''
    modifiers = f' {_to_yara(node.modifiers)}' if node.modifiers else ''
    if node.type == 'text':
        return f'${identifier} = "{node.value}"{modifiers}'

    elif node.type == 'hex':
        return f'${identifier} = {{ {node.value} }}{modifiers}'

    elif node.type == 'regex':
        return f'${identifier} = /{node.value}/{modifiers}'

    else:
        raise RuntimeError(f'Unrecognized string type: {node.type}')


@_to_yara.register(Modifiers)
def _(node):
    return ' '.join(_to_yara(modifier) for modifier in node.modifiers)


@_to_yara.register(Modifier)
def _(node):
    parameter = f'{_to_yara(node.parameter)}' if node.parameter else ''
    return f'{node.modifier}{parameter}'


@_to_yara.register(Alphabet)
def _(node):
    return f'("{node.value}")'


@_to_yara.register(Range)
def _(node):
    return f'(0x{node.minimum}-0x{node.maximum})'


@_to_yara.register(Condition)
def _(node):
    return '        '.join(_to_yara(expr) for expr in node.conditions)


@_to_yara.register(Boolean)
def _(node):
    return 'true' if node.value else 'false'


@_to_yara.register(Variable)
def _(node):
    if node.type == 'boolean':
        return f'${node.identifier}'

    elif node.type == 'offset':
        return f'@{node.identifier}'

    elif node.type == 'count':
        return f'#{node.identifier}'

    elif node.type == 'length':
        return f'!{node.identifier}'

    else:
        raise RuntimeError(f'Unrecognized variable type: {node.type}')
