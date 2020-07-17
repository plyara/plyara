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

from .model import Statements, Rule, Meta, MetaDeclaration, Condition, Boolean


def to_yara(node):
    return _to_yara(node)


@singledispatch
def _to_yara(node):
    raise RuntimeError(f'Unrecognized node {node}')


@_to_yara.register(Statements)
def _(node):
    return ''.join(_to_yara(stmt) for stmt in node.statements)


@_to_yara.register(Rule)
def _(node):
    pri = f'{node.private_rtbype} ' if node.private_rtype else ''
    glo = f'{node.global_rtype} ' if node.global_rtype else ''
    tags = f' : {_to_yara(node.tags)}' if node.tags else ''
    meta = f'    meta:\n        {_to_yara(node.meta)}\n' if node.meta else ''
    strings = f'    strings:\n        {_to_yara(node.strings)}\n' if node.strings else ''
    condition = f'    condition:\n        {_to_yara(node.condition)}\n' if node.condition else ''

    return f'{pri}{glo}rule {node.name}{tags}\n{{\n{meta}{strings}{condition}}}\n'


@_to_yara.register(Meta)
def _(node):
    return '        '.join(_to_yara(decl) for decl in node.meta_declarations)


@_to_yara.register(MetaDeclaration)
def _(node):
    if node.type == 'string':
        return f'{node.name} = "{node.value}"'

    elif node.type == 'number':
        return f'{node.name} = {node.value}'

    else:
        if node.value:
            return f'{node.name} = true'
        else:
            return f'{node.name} = false'


@_to_yara.register(Condition)
def _(node):
    return '        '.join(_to_yara(expr) for expr in node.conditions)


@_to_yara.register(Boolean)
def _(node):
    return 'true' if node.value else 'false'
