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
"""Python data model of YARA.

This model is composed of classes and data structures that represent the source
code of a YARA rule.
"""


class Node:
    """Base class."""

    pass


class Statement(Node):
    """Everything is a statement at the level of a ruleset excluding comments."""

    pass


class Statements:
    """Basically a list of statements making up a ruleset."""

    def __init__(self, statements):
        """Initialize Statements class."""
        assert all(isinstance(stmt, Statement) for stmt in statements)
        self.statements = statements

    def __repr__(self):
        """Text representation of Statements class."""
        return f'Statements({self.statements})'


class Include(Statement):
    """Includes rules from a different ruleset file."""

    def __init__(self, path):
        """Initialize Include class."""
        assert isinstance(path, str)
        self.path = path

    def __repr__(self):
        """Text representation of Include class."""
        return f'Include({self.path})'


class Import(Statement):
    """Module import statement."""

    def __init__(self, module):
        """Initialize Import class."""
        assert isinstance(module, str)
        self.module = module

    def __repr__(self):
        """Text representation of Import class."""
        return f'Import({self.module})'


class Rule(Statement):
    """Main node for a rule including rule typing and contents."""

    def __init__(self, identifier, rule_types, tags, meta, strings, condition):
        """Initialize Rule class."""
        assert isinstance(identifier, str)
        assert rule_types is None or isinstance(rule_types, RuleTypes)
        assert tags is None or isinstance(tags, Tags)
        assert meta is None or isinstance(meta, Meta)
        assert strings is None or isinstance(strings, Strings)
        assert isinstance(condition, Condition)
        self.rule_types = rule_types
        self.identifier = identifier
        self.tags = tags
        self.meta = meta
        self.strings = strings
        self.condition = condition

    def __repr__(self):
        """Text representation of Rule class."""
        return f'Rule({self.identifier}, {self.rule_types}, {self.tags}, {self.meta}, {self.strings}, {self.condition})'


class RuleTypes:
    """Rule types."""

    def __init__(self, rule_types):
        """Initialize RuleTypes class."""
        assert all(isinstance(rule_type, RuleType) for rule_type in rule_types)
        self.rule_types = rule_types

    def __repr__(self):
        """Text representation of RuleTypes class."""
        return f'RuleTypes({self.rule_types})'


class RuleType(Node):
    """Single rule type."""

    def __init__(self, value):
        """Initialize RuleType class."""
        assert isinstance(value, str)
        self.value = value

    def __repr__(self):
        """Text representation of RuleType class."""
        return f'RuleType({self.value})'


class Tags:
    """Rule tags."""

    def __init__(self, tags):
        """Initialize Tags class."""
        assert all(isinstance(tag, Tag) for tag in tags)
        self.tags = tags

    def __repr__(self):
        """Text representation of Tags class."""
        return f'Tags({self.tags})'


class Tag(Node):
    """Single rule tag."""

    def __init__(self, value):
        """Initialize Tag class."""
        assert isinstance(value, str)
        self.value = value

    def __repr__(self):
        """Text representation of Tag class."""
        return f'Tag({self.value})'


class Section:
    """Sections of a rule include meta, strings, and condition. Condition is required."""

    pass


class Definition(Statement):
    """Used in both meta and string sections of a rule."""

    pass


class Meta(Section):
    """Meta section of a rule."""

    def __init__(self, definitions):
        """Initialize Meta class."""
        assert all(isinstance(definition, Definition) for definition in definitions)
        self.definitions = definitions

    def __repr__(self):
        """Text representation of Meta class."""
        return f'Meta({self.definitions})'


class MetaDefinition(Definition):
    """Declares one value of metadata."""

    def __init__(self, identifier, type, value):
        """Initialize MetaDeclaration class."""
        assert isinstance(identifier, str)
        assert isinstance(type, str)
        assert isinstance(value, str) or isinstance(value, int) or isinstance(value, bool)
        self.identifier = identifier
        self.type = type
        self.value = value

    def __repr__(self):
        """Text representation of MetaDeclaration class."""
        return f'MetaDeclaration({self.identifier}, {self.type}, {self.value})'


class Strings(Section):
    """Strings section of a rule."""

    def __init__(self, strings):
        """Initialize Strings class."""
        assert all(isinstance(definition, Definition) for definition in strings)
        self.strings = strings

    def __repr__(self):
        """Text representation of Strings class."""
        return f'Strings({self.strings})'


class Modifiers:
    """String modifiers."""

    def __init__(self, modifiers):
        """Initialize Modifiers class."""
        assert all(isinstance(mod, Modifier) for mod in modifiers)
        self.modifiers = modifiers

    def __repr__(self):
        """Text representation of Modifiers class."""
        return f'Modifiers({self.modifiers})'


class Modifier(Node):
    """Single modifier."""

    def __init__(self, modifier, parameter):
        """Initialize Modifier class."""
        assert isinstance(modifier, str)
        assert parameter is None or isinstance(parameter, Parameter)
        self.modifier = modifier
        self.parameter = parameter

    def __repr__(self):
        """Text representation of Modifier class."""
        return f'Modifier({self.modifier}, {self.parameter})'


class Parameter(Node):
    """Parameter of a modifier."""

    pass


class Alphabet(Parameter):
    """Custom alphabet parameter for base64 and base64wide modifiers."""

    def __init__(self, value):
        """Initialize Alphabet class."""
        assert isinstance(value, str)
        self.value = value

    def __repr__(self):
        """Text representation of Alphabet class."""
        return f'Alphabet({self.value})'


class Range(Parameter):
    """Custom range of bytes used with xor modifier."""

    def __init__(self, minimum, maximum):
        """Initialize Range class."""
        assert isinstance(minimum, str)
        assert isinstance(maximum, str)
        self.minimum = minimum
        self.maximum = maximum

    def __repr__(self):
        """Text representation of Range class."""
        return f'Range({self.minimum}, {self.maximum})'


class StrDefinition(Definition):
    """Declares one string."""

    def __init__(self, identifier, type, value, modifiers):
        """Initialize StrDefinition class."""
        assert isinstance(identifier, str)
        assert isinstance(type, str)
        assert isinstance(value, str)
        assert modifiers is None or isinstance(modifiers, Modifiers)
        self.identifier = identifier
        self.type = type
        self.value = value
        self.modifiers = modifiers

    def __repr__(self):
        """Text representation of StrDefinition class."""
        return f'StrDefinition({self.identifier}, {self.type}, {self.value}, {self.modifiers})'


class Expression(Statement):
    """One condition expression."""

    pass


class Condition(Section):
    """Condition section of a rule."""

    def __init__(self, conditions):
        """Initialize Condition class."""
        assert all(isinstance(expr, Expression) for expr in conditions)
        self.conditions = conditions

    def __repr__(self):
        """Text representation of Condition class."""
        return f'Condition({self.conditions})'


class Boolean(Expression):
    """Boolean expression."""

    def __init__(self, value):
        """Initialize Boolean class."""
        assert isinstance(value, bool)
        self.value = value

    def __repr__(self):
        """Text representation of Boolean class."""
        return f'Boolean({self.value})'


class Variable(Expression):
    """Variable expression."""

    def __init__(self, identifier, type):
        """Initialize Variable class."""
        assert isinstance(identifier, str)
        assert isinstance(type, str)
        self.identifier = identifier
        self.type = type

    def __repr__(self):
        """Text representation of Variable class."""
        return f'Variable({self.identifier}, {self.type})'
