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


class Expression(Statement):
    """Used in conditions and evaluates to a number or string."""

    pass


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

    def __init__(self, private_rtype, global_rtype, name, tags, meta, strings, condition):
        """Initialize Rule class."""
        assert private_rtype is None or isinstance(private_rtype, str)
        assert private_rtype is None or isinstance(global_rtype, str)
        assert isinstance(name, str)
        assert tags is None or isinstance(tags, Tags)
        assert meta is None or isinstance(meta, Meta)
        assert strings is None or isinstance(strings, Strings)
        assert isinstance(condition, Condition)
        self.private_rtype = private_rtype
        self.global_rtype = global_rtype
        self.name = name
        self.tags = tags
        self.meta = meta
        self.strings = strings
        self.condition = condition

    def __repr__(self):
        """Text representation of Rule class."""
        return f'Rule({self.private_rtype}, {self.global_rtype}, {self.name}, {self.tags}, {self.meta}, {self.strings}, {self.condition})'


class Tags:
    """Rule tags."""

    def __init__(self, tags):
        """Initialize Tags class."""
        assert all(isinstance(tag, Statement) for tag in tags)
        self.tags = tags

    def __repr__(self):
        """Text representation of Tags class."""
        return f'Tags({self.tags})'


class Tag:
    """Single rule tag."""

    def __init__(self, value):
        """Initialize Tag class."""
        assert isinstance(value, str)
        self.value = value

    def __repr__(self):
        """Text representation of Tag class."""
        return f'Tag({self.value})'


class Section(Node):
    """Sections of a rule include meta, strings, and condition. Condition is required."""

    pass


class Declaration(Statement):
    """Used in both meta and string sections of a rule."""

    pass


class Meta(Section):
    """Meta section of a rule."""

    def __init__(self, meta_declarations):
        """Initialize Meta class."""
        assert all(isinstance(decl, Declaration) for decl in meta_declarations)
        self.meta_declarations = meta_declarations

    def __repr__(self):
        """Text representation of Meta class."""
        return f'Meta({self.meta_declarations})'


class MetaDeclaration(Declaration):
    """Declares one value of metadata."""

    def __init__(self, name, type, value):
        assert isinstance(name, str)
        assert isinstance(type, str)
        assert isinstance(value, str)
        self.name = name
        self.type = type
        self.value = value

    def __repr__(self):
        return f'MetaDeclaration({self.name}, {self.type}, {self.value})'


class Strings(Section):
    """Strings section of a rule."""

    def __init__(self, strings):
        """Initialize Strings class."""
        assert all(isinstance(decl, Declaration) for decl in strings)
        self.strings = strings

    def __repr__(self):
        """Text representation of Strings class."""
        return f'Strings({self.strings})'


class StringDeclaration(Declaration):
    """Declares one string."""

    def __init__(self, name, type, value):
        assert isinstance(name, str)
        assert isinstance(type, str)
        assert isinstance(value, str)
        self.name = name
        self.type = type
        self.value = value

    def __repr__(self):
        return f'StringDeclaration({self.name}, {self.type}, {self.value})'


class Condition(Section):
    """Condition section of a rule."""

    def __init__(self, conditions):
        """Initialize Condition class."""
        assert all(isinstance(expr, Expression) for expr in conditions)
        self.conditions = conditions

    def __repr__(self):
        """Text representation of Condition class."""
        return f'Condition({self.conditions})'
