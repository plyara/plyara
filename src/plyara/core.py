# Copyright 2014 Christian Buia
# Copyright 2025 plyara Maintainers
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
"""Parse YARA rules and operate over them more easily.

Plyara is a script and library that lexes and parses a file consisting of one more YARA rules into a python
dictionary representation. The goal of this tool is to make it easier to perform bulk operations or transformations of
large sets of YARA rules, such as extracting indicators, updating attributes, and analyzing a corpus. Other applications
include linters and dependency checkers.
"""
import enum
import logging
import re
import string
import tempfile

import ply.lex as lex
import ply.yacc as yacc

from plyara.exceptions import ParseTypeError, ParseValueError

# Initialize the logger
logger = logging.getLogger(__name__)


class ElementTypes(enum.Enum):
    """An enumeration of the element types emitted by the parser to the interpreter."""

    RULE_NAME = 1
    METADATA_KEY_VALUE = 2
    STRINGS_KEY_VALUE = 3
    STRINGS_MODIFIER = 4
    IMPORT = 5
    TERM = 6
    SCOPE = 7
    TAG = 8
    INCLUDE = 9
    COMMENT = 10
    MCOMMENT = 11


class StringTypes(enum.Enum):
    """String types found in a YARA rule."""

    TEXT = 1
    BYTE = 2
    REGEX = 3


class Parser:
    """Interpret the output of the parser and produce an alternative representation of YARA rules."""

    EXCLUSIVE_TEXT_MODIFIERS = {'nocase', 'xor', 'base64'}

    COMPARISON_OPERATORS = {'==', '!=', '>', '<', '>=', '<='}

    IMPORT_OPTIONS = {
        'androguard',
        'console',
        'cuckoo',
        'dex',
        'dotnet',
        'elf',
        'hash',
        'lnk',
        'macho',
        'magic',
        'math',
        'pe',
        'string',
        'time',
        'vt'
    }

    KEYWORDS = {
        'all',
        'and',
        'any',
        'ascii',
        'at',
        'base64',
        'base64wide',
        'condition',
        'contains',
        'defined',
        'endswith',
        'entrypoint',
        'false',
        'filesize',
        'for',
        'fullword',
        'global',
        'icontains',
        'iendswith',
        'iequals',
        'import',
        'in',
        'include',
        'int16',
        'int16be',
        'int32',
        'int32be',
        'int8',
        'int8be',
        'istartswith',
        'matches',
        'meta',
        'nocase',
        'none',
        'not',
        'of',
        'or',
        'private',
        'rule',
        'startswith',
        'strings',
        'them',
        'true',
        'uint16',
        'uint16be',
        'uint32',
        'uint32be',
        'uint8',
        'uint8be',
        'wide',
        'xor'
    }

    FUNCTION_KEYWORDS = {'uint8', 'uint16', 'uint32', 'uint8be', 'uint16be', 'uint32be'}

    def __init__(self, store_raw_sections=True, meta_as_kv=False, import_effects=False):
        """Initialize the parser object.

        Args:
            store_raw_sections: Enable attribute storage of raw section input. (default True)
            meta_as_kv: Enable alternate structure for meta section as dictionary. (default False)
            import_effects: Enable including imports in all rules affected by the import. (default False)
        """
        self.rules = list()

        self.current_rule = dict()

        self.string_modifiers = list()
        self.imports = set()
        self.includes = list()
        self.terms = list()
        self.scopes = list()
        self.tags = list()
        self.comments = list()

        # adds functionality to track attributes containing raw section data
        # in case needed (ie modifying metadata and re-constructing a complete rule
        # while maintaining original comments and padding)
        self.store_raw_sections = store_raw_sections
        self._raw_input = None
        self._meta_start = None
        self._meta_end = None
        self._strings_start = None
        self._strings_end = None
        self._condition_start = None
        self._condition_end = None
        self._rule_comments = list()
        self._stringnames = set()

        # Adds a dictionary representation of the meta section of a rule
        self.meta_as_kv = meta_as_kv

        # Includes imports in all rules affected by them whether or not the import is used in a condition
        self.import_effects = import_effects

        self.lexer = lex.lex(module=self, debug=False)
        self.parser = yacc.yacc(module=self, debug=False, outputdir=tempfile.gettempdir())

    def clear(self):
        """Clear all information about previously parsed rules."""
        self.rules.clear()

        self.current_rule.clear()

        self.string_modifiers.clear()
        self.imports.clear()
        self.includes.clear()
        self.terms.clear()
        self.scopes.clear()
        self.tags.clear()
        self.comments.clear()

        self._raw_input = None
        self._meta_start = None
        self._meta_end = None
        self._strings_start = None
        self._strings_end = None
        self._condition_start = None
        self._condition_end = None
        self._rule_comments.clear()
        self._stringnames.clear()

        self.lexer = lex.lex(module=self, debug=False)
        self.parser = yacc.yacc(module=self, debug=False, outputdir=tempfile.gettempdir())

    def _add_element(self, element_type, element_value):
        """Accept elements from the parser and uses them to construct a representation of the YARA rule.

        Args:
            element_type: The element type determined by the parser. Input is one of ElementTypes.
            element_value: This is the contents of the element as parsed from the rule.
        """
        if element_type == ElementTypes.RULE_NAME:
            rule_name, start_line, stop_line = element_value
            self.current_rule['rule_name'] = rule_name
            self.current_rule['start_line'] = start_line
            self.current_rule['stop_line'] = stop_line

            if self.store_raw_sections:
                if self._meta_start:
                    self.current_rule['raw_meta'] = self._raw_input[self._meta_start:self._meta_end]

                if self._strings_start:
                    self.current_rule['raw_strings'] = self._raw_input[self._strings_start:self._strings_end]

                if self._condition_start:
                    self.current_rule['raw_condition'] = self._raw_input[self._condition_start:self._condition_end]

            self._flush_accumulators()

            self.rules.append(self.current_rule)
            logger.debug('Adding Rule: {}'.format(self.current_rule['rule_name']))
            self.current_rule = dict()
            self._stringnames.clear()

        elif element_type == ElementTypes.METADATA_KEY_VALUE:
            key, value = element_value

            if 'metadata' not in self.current_rule:
                self.current_rule['metadata'] = [{key: value}]
                if self.meta_as_kv:
                    self.current_rule['metadata_kv'] = {key: value}
            else:
                self.current_rule['metadata'].append({key: value})
                if self.meta_as_kv:
                    self.current_rule['metadata_kv'][key] = value

        elif element_type == ElementTypes.STRINGS_KEY_VALUE:
            key, value, string_type = element_value

            string_dict = {'name': key, 'value': value, 'type': string_type.name.lower()}

            if any(self.string_modifiers):
                string_dict['modifiers'] = self.string_modifiers
                self.string_modifiers = list()

            if 'strings' not in self.current_rule:
                self.current_rule['strings'] = [string_dict]
            else:
                self.current_rule['strings'].append(string_dict)

        elif element_type == ElementTypes.STRINGS_MODIFIER:
            self.string_modifiers.append(element_value)

        elif element_type == ElementTypes.IMPORT:
            self.imports.add(element_value)

        elif element_type == ElementTypes.INCLUDE:
            self.includes.append(element_value)

        elif element_type == ElementTypes.TERM:
            self.terms.append(element_value)

        elif element_type == ElementTypes.SCOPE:
            self.scopes.append(element_value)

        elif element_type == ElementTypes.TAG:
            self.tags.append(element_value)

        elif element_type == ElementTypes.COMMENT:
            self.comments.append(element_value)

        else:
            self.comments.append(element_value)

    def _flush_accumulators(self):
        """Add accumulated elements to the current rule and resets the accumulators."""
        if any(self.terms):
            self.current_rule['condition_terms'] = self.terms
            self.terms = list()

        if any(self.scopes):
            self.current_rule['scopes'] = self.scopes
            self.scopes = list()

        if any(self.tags):
            self.current_rule['tags'] = self.tags
            self.tags = list()

        if any(self.comments):
            self.current_rule['comments'] = self.comments
            self.comments = list()

        self._meta_start = None
        self._meta_end = None
        self._strings_start = None
        self._strings_end = None
        self._condition_start = None
        self._condition_end = None

    @staticmethod
    def _find_imports_in_condition(imports, condition_terms):
        """Search a list of condition terms for any that use the given imports."""
        used_imports = set()

        for imp in imports:
            for term in condition_terms:
                if term.startswith(f'{imp}.'):
                    used_imports.add(imp)
                    break

        return list(used_imports)

    def parse_string(self, input_string):
        """Take a string input expected to consist of YARA rules, and return list of dictionaries representing them.

        Args:
            input_string: String input expected to consist of YARA rules.

        Returns:
            dict: All the parsed components of a YARA rule.
        """
        self._raw_input = input_string
        self.parser.parse(input_string, lexer=self.lexer)

        for rule in self.rules:
            if any(self.imports):
                if self.import_effects:
                    rule['imports'] = list(self.imports)
                elif imports := self._find_imports_in_condition(self.imports, rule['condition_terms']):
                    rule['imports'] = imports
            if any(self.includes):
                rule['includes'] = self.includes

        return self.rules


class Plyara(Parser):
    """Define the lexer and the parser rules."""

    STRING_ESCAPE_CHARS = {'"', '\\', 't', 'n', 'x', 'r'}

    tokens = [
        'BYTESTRING',
        'STRING',
        'REXSTRING',
        'EQUALS',
        'STRINGNAME',
        'STRINGNAME_ARRAY',
        'STRINGNAME_COUNT',
        'STRINGNAME_LENGTH',
        'LPAREN',
        'RPAREN',
        'LBRACK',
        'RBRACK',
        'LBRACE',
        'RBRACE',
        'ID',
        'BACKSLASH',
        'PIPE',
        'PLUS',
        'SECTIONMETA',
        'SECTIONSTRINGS',
        'SECTIONCONDITION',
        'COMMA',
        'GREATERTHAN',
        'LESSTHAN',
        'GREATEREQUAL',
        'LESSEQUAL',
        'RIGHTBITSHIFT',
        'LEFTBITSHIFT',
        'MODULO',
        'TILDE',
        'XOR_OP',  # XOR operator token (from conditions section)
        'PERIOD',
        'COLON',
        'STAR',
        'HYPHEN',
        'AMPERSAND',
        'NEQUALS',
        'EQUIVALENT',
        'DOTDOT',
        'HEXNUM',
        'FILESIZE_SIZE',
        'NUM',
        'COMMENT',
        'MCOMMENT'
    ]

    reserved = {
        'all': 'ALL',
        'and': 'AND',
        'any': 'ANY',
        'ascii': 'ASCII',
        'at': 'AT',
        'contains': 'CONTAINS',
        'defined': 'DEFINED',
        'entrypoint': 'ENTRYPOINT',
        'false': 'FALSE',
        'filesize': 'FILESIZE',
        'for': 'FOR',
        'fullword': 'FULLWORD',
        'global': 'GLOBAL',
        'import': 'IMPORT',
        'in': 'IN',
        'include': 'INCLUDE',
        'int8': 'INT8',
        'int16': 'INT16',
        'int32': 'INT32',
        'int8be': 'INT8BE',
        'int16be': 'INT16BE',
        'int32be': 'INT32BE',
        'matches': 'MATCHES',
        'nocase': 'NOCASE',
        'none': 'NONE',
        'not': 'NOT',
        'of': 'OF',
        'or': 'OR',
        'private': 'PRIVATE',
        'rule': 'RULE',
        'them': 'THEM',
        'true': 'TRUE',
        'wide': 'WIDE',
        'uint8': 'UINT8',
        'uint16': 'UINT16',
        'uint32': 'UINT32',
        'uint8be': 'UINT8BE',
        'uint16be': 'UINT16BE',
        'uint32be': 'UINT32BE',
        'xor': 'XOR_MOD',  # XOR string modifier token (from strings section)
        'base64': 'BASE64',
        'base64wide': 'BASE64WIDE',
        'icontains': 'ICONTAINS',
        'endswith': 'ENDSWITH',
        'iendswith': 'IENDSWITH',
        'startswith': 'STARTSWITH',
        'istartswith': 'ISTARTSWITH',
        'iequals': 'IEQUALS'
    }

    tokens = tokens + list(reserved.values())

    # Regular expression rules for simple tokens
    t_LPAREN = r'\('
    t_RPAREN = r'\)'
    t_EQUIVALENT = r'=='
    t_NEQUALS = r'!='
    t_EQUALS = r'='
    t_LBRACE = r'{'
    t_PLUS = r'\+'
    t_PIPE = r'\|'
    t_BACKSLASH = r'\\'
    t_COMMA = r','
    t_GREATERTHAN = r'>'
    t_LESSTHAN = r'<'
    t_GREATEREQUAL = r'>='
    t_LESSEQUAL = r'<='
    t_RIGHTBITSHIFT = r'>>'
    t_LEFTBITSHIFT = r'<<'
    t_MODULO = r'%'
    t_TILDE = r'~'
    t_XOR_OP = r'\^'
    t_PERIOD = r'\.'
    t_COLON = r':'
    t_STAR = r'\*'
    t_LBRACK = r'\['
    t_RBRACK = r'\]'
    t_HYPHEN = r'\-'
    t_AMPERSAND = r'&'
    t_DOTDOT = r'\.\.'

    states = (
        ('STRING', 'exclusive', ),
        ('BYTESTRING', 'exclusive', ),
        ('REXSTRING', 'exclusive', ),
    )

    # Complex token handling
    def t_RBRACE(self, t):
        r'}'  # noqa: D300, D400, D415
        t.value = t.value
        self._condition_end = t.lexpos

        return t

    @staticmethod
    def t_NEWLINE(t):
        r'(\n|\r\n)+'  # noqa: D300, D400, D415
        t.lexer.lineno += len(t.value)
        t.value = t.value

    @staticmethod
    def t_COMMENT(t):
        r'(//[^\r\n]*)'  # noqa: D300, D400, D415
        return t

    @staticmethod
    def t_MCOMMENT(t):
        r'/\*(.|\n|\r\n)*?\*/'  # noqa: D300, D400, D415
        if '\r\n' in t.value:
            t.lexer.lineno += t.value.count('\r\n')
        else:
            t.lexer.lineno += t.value.count('\n')

        return t

    @staticmethod
    def t_HEXNUM(t):
        r'0x[A-Fa-f0-9]+'  # noqa: D300, D400, D415
        t.value = t.value

        return t

    def t_SECTIONMETA(self, t):
        r'meta\s*:'  # noqa: D300, D400, D415
        t.value = t.value
        self._meta_start = t.lexpos
        t.lexer.section = 'meta'

        return t

    def t_SECTIONSTRINGS(self, t):
        r'strings\s*:'  # noqa: D300, D400, D415
        t.value = t.value
        self._strings_start = t.lexpos
        self._meta_end = t.lexpos
        t.lexer.section = 'strings'

        return t

    def t_SECTIONCONDITION(self, t):
        r'condition\s*:'  # noqa: D300, D400, D415
        t.value = t.value
        self._condition_start = t.lexpos
        if self._meta_end is None:
            self._meta_end = t.lexpos
        self._strings_end = t.lexpos
        t.lexer.section = 'condition'

        return t

    # Text string handling
    @staticmethod
    def t_begin_STRING(t):
        r'"'  # noqa: D300, D400, D415
        t.lexer.escape = 0
        t.lexer.string_start = t.lexer.lexpos - 1
        t.lexer.begin('STRING')
        t.lexer.hex_escape = 0

    # @staticmethod
    def t_STRING_value(self, t):
        r'(\S|\x20)'  # noqa: D300, D400, D415
        if t.lexer.escape == 0 and t.value == '"':
            t.type = 'STRING'
            t.value = t.lexer.lexdata[t.lexer.string_start:t.lexer.lexpos]
            t.lexer.begin('INITIAL')

            return t

        else:
            self._process_string_with_escapes(t, escape_chars=self.STRING_ESCAPE_CHARS)

    t_STRING_ignore = ''

    @staticmethod
    def t_STRING_error(t):
        """Raise parsing error for illegal string character.

        Args:
            t: Token input from lexer.

        Raises:
            ParseTypeError
        """
        msg = 'Illegal string character: {!r}, at line: {}'
        raise ParseTypeError(msg.format(t.value[0], t.lexer.lineno), t.lexer.lineno, t.lexer.lexpos)

    # Byte string handling
    @staticmethod
    def t_begin_BYTESTRING(t):
        r'\{'  # noqa: D300, D400, D415
        if hasattr(t.lexer, 'section') and t.lexer.section == 'strings':
            t.lexer.bytestring_start = t.lexer.lexpos - 1
            t.lexer.begin('BYTESTRING')
            t.lexer.bytestring_group = 0
        else:
            t.type = 'LBRACE'

            return t

    @staticmethod
    def t_BYTESTRING_pair(t):
        r'\s*~?[a-fA-F0-9?]{2}\s*'  # noqa: D300, D400, D415

    @staticmethod
    def t_BYTESTRING_comment(t):
        r'\/\/[^\r\n]*'  # noqa: D300, D400, D415
        t.type = 'COMMENT'

        return t

    @staticmethod
    def t_BYTESTRING_mcomment(t):
        r'/\*(.|\n|\r\n)*?\*/'  # noqa: D300, D400, D415
        t.type = 'MCOMMENT'

        return t

    @staticmethod
    def t_BYTESTRING_jump(t):
        r'\[\s*(\d*)\s*-?\s*(\d*)\s*\]'  # noqa: D300, D400, D415
        groups = t.lexer.lexmatch.groups()
        index = groups.index(t.value)

        lower_bound = groups[index + 1]
        upper_bound = groups[index + 2]

        if lower_bound and upper_bound:
            if not 0 <= int(lower_bound) <= int(upper_bound):
                raise ParseValueError(f'Illegal bytestring jump bounds: {t.value}, at line: {t.lexer.lineno}',
                                      t.lexer.lineno, t.lexer.lexpos)

    @staticmethod
    def t_BYTESTRING_group_start(t):
        r'\('  # noqa: D300, D400, D415
        t.lexer.bytestring_group += 1

    @staticmethod
    def t_BYTESTRING_group_end(t):
        r'\)'  # noqa: D300, D400, D415
        t.lexer.bytestring_group -= 1

    @staticmethod
    def t_BYTESTRING_group_logical_or(t):
        r'\|'  # noqa: D300, D400, D415

    @staticmethod
    def t_BYTESTRING_end(t):
        r'\}'  # noqa: D300, D400, D415
        t.type = 'BYTESTRING'
        t.value = t.lexer.lexdata[t.lexer.bytestring_start:t.lexer.lexpos]

        if t.lexer.bytestring_group != 0:
            raise ParseValueError(f'Unbalanced group in bytestring: {t.value}, at line: {t.lexer.lineno}',
                                  t.lexer.lineno, t.lexer.lexpos)

        t.lexer.begin('INITIAL')

        # Account for newlines in bytestring.
        if '\r\n' in t.value:
            t.lexer.lineno += t.value.count('\r\n')
        else:
            t.lexer.lineno += t.value.count('\n')

        return t

    t_BYTESTRING_ignore = ' \r\n\t'

    @staticmethod
    def t_BYTESTRING_error(t):
        """Raise parsing error for illegal bytestring character.

        Args:
            t: Token input from lexer.

        Raises:
            ParseTypeError
        """
        raise ParseTypeError(f'Illegal bytestring character : {t.value[0]}, at line: {t.lexer.lineno}',
                             t.lexer.lineno, t.lexer.lexpos)

    # Rexstring Handling
    @staticmethod
    def t_begin_REXSTRING(t):
        r'/'  # noqa: D300, D400, D415
        t.lexer.rexstring_start = t.lexer.lexpos - 1
        t.lexer.begin('REXSTRING')
        t.lexer.escape = 0
        t.lexer.hex_escape = 0

    @staticmethod
    def t_REXSTRING_end(t):
        r'/(?:i?s?)'  # noqa: D300, D400, D415
        if t.lexer.escape == 0:
            t.type = 'REXSTRING'
            t.value = t.lexer.lexdata[t.lexer.rexstring_start:t.lexer.lexpos]
            t.lexer.begin('INITIAL')

            return t
        else:
            t.lexer.escape ^= 1

    def t_REXSTRING_value(self, t):
        r'[\x20-\x7f]'  # noqa: D300, D400, D415
        self._process_string_with_escapes(t)

    t_REXSTRING_ignore = ''

    @staticmethod
    def t_REXSTRING_error(t):
        """Raise parsing error for illegal rexstring character.

        Args:
            t: Token input from lexer.

        Raises:
            ParseTypeError
        """
        msg = 'Illegal rexstring character : {!r}, at line: {}'
        raise ParseTypeError(msg.format(t.value[0], t.lexer.lineno), t.lexer.lineno, t.lexer.lexpos)

    @staticmethod
    def t_STRINGNAME(t):
        r'\$[0-9a-zA-Z_]*[*]?'  # noqa: D300, D400, D415
        t.value = t.value

        return t

    @staticmethod
    def t_STRINGNAME_ARRAY(t):
        r'@[0-9a-zA-Z_]*[*]?'  # noqa: D300, D400, D415
        t.value = t.value

        return t

    @staticmethod
    def t_STRINGNAME_LENGTH(t):
        r'![0-9a-zA-Z_]*[*]?(?!=)'  # noqa: D300, D400, D415
        t.value = t.value

        return t

    @staticmethod
    def t_STRINGNAME_COUNT(t):
        r'\#([a-zA-Z][0-9a-zA-Z_]*[*]?)?'  # noqa: D300, D400, D415
        t.value = t.value

        return t

    @staticmethod
    def t_FILESIZE_SIZE(t):
        r"\d+[KM]B"  # noqa: D300, D400, D415
        t.value = t.value

        return t

    @staticmethod
    def t_NUM(t):
        r'\d+(\.\d+)?'  # noqa: D300, D400, D415
        t.value = t.value

        return t

    def t_ID(self, t):
        r'[a-zA-Z_][a-zA-Z_0-9.]*'  # noqa: D300, D400, D415
        t.type = self.reserved.get(t.value, 'ID')  # Check for reserved words

        return t

    # A string containing ignored characters (spaces and tabs)
    t_ignore = ' \t'

    # Error handling rule
    @staticmethod
    def t_error(t):
        """Raise parsing error.

        Args:
            t: Token input from lexer.

        Raises:
            ParseTypeError
        """
        msg = 'Illegal character {!r} at line {}'
        raise ParseTypeError(msg.format(t.value[0], t.lexer.lineno), t.lexer.lineno, t.lexer.lexpos)

    # Parsing rules
    precedence = (
        ('right', 'NUM', ),
        ('right', 'ID', ),
        ('right', 'HEXNUM', )
    )

    @staticmethod
    def p_ruleset(p):
        '''ruleset : rules
                   | imports
                   | includes
                   | ruleset ruleset'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    @staticmethod
    def p_rules(p):
        '''rules : rules rule
                 | rule'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    def p_rule(self, p):
        '''rule : scopes RULE ID tag_section LBRACE rule_body RBRACE
                | scopes RULE ID tag_section LBRACE rule_body RBRACE comments'''  # noqa: D300, D400, D403, D415
        logger.debug(f'Matched rule: {p[3]}')
        if '.' in p[3]:
            raise ParseTypeError(f'Invalid rule name {p[3]}, on line {p.lineno(1)}', p.lineno, p.lexpos)
        logger.debug(f'Rule start: {p.lineno(2)}, Rule stop: {p.lineno(7)}')

        while self._rule_comments:
            comment = self._rule_comments.pop()

            if p.lexpos(5) < comment.lexpos < p.lexpos(7):
                self._add_element(getattr(ElementTypes, comment.type), comment.value)

        element_value = (p[3], int(p.lineno(2)), int(p.lineno(7)), )
        self._add_element(ElementTypes.RULE_NAME, element_value)

    @staticmethod
    def p_imports(p):
        '''imports : imports import
                   | import'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    @staticmethod
    def p_includes(p):
        '''includes : includes include
                    | include'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    @staticmethod
    def p_scopes(p):
        '''scopes : scopes scope
                  | scope
                  | '''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    def p_import(self, p):
        '''import : IMPORT STRING'''  # noqa: D300, D400, D403, D415
        import_value = p[2].replace('"', '')
        logger.debug(f'Matched import: {import_value}')
        self._add_element(ElementTypes.IMPORT, import_value)

    def p_include(self, p):
        '''include : INCLUDE STRING'''  # noqa: D300, D400, D403, D415
        include_value = p[2].replace('"', '')
        logger.debug(f'Matched include: {include_value}')
        self._add_element(ElementTypes.INCLUDE, include_value)

    def p_scope(self, p):
        '''scope : PRIVATE
                 | GLOBAL'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        logger.debug(f'Matched scope identifier: {p[1]}')
        self._add_element(ElementTypes.SCOPE, p[1])

    @staticmethod
    def p_tag_section(p):
        '''tag_section : COLON tags
                       | COLON tags comments
                       | comments
                       | '''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    @staticmethod
    def p_tags(p):
        '''tags : tags tag
                | tag'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    def p_tag(self, p):
        '''tag : ID'''  # noqa: D300, D400, D403, D415
        logger.debug(f'Matched tag: {p[1]}')
        self._add_element(ElementTypes.TAG, p[1])

    @staticmethod
    def p_rule_body(p):
        '''rule_body : sections
                     | comments sections'''  # noqa: D300, D400, D403, D415
        logger.debug('Matched rule body')

    @staticmethod
    def p_rule_sections(p):
        '''sections : sections section
                    | section'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    @staticmethod
    def p_rule_section(p):
        '''section : meta_section
                   | strings_section
                   | condition_section'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    @staticmethod
    def p_meta_section(p):
        '''meta_section : SECTIONMETA meta_kvs
                        | SECTIONMETA comments meta_kvs'''  # noqa: D300, D400, D403, D415
        logger.debug('Matched meta section')

    @staticmethod
    def p_strings_section(p):
        '''strings_section : SECTIONSTRINGS strings_kvs
                           | SECTIONSTRINGS comments strings_kvs'''  # noqa: D300, D400, D403, D415

    @staticmethod
    def p_condition_section(p):
        '''condition_section : SECTIONCONDITION expression
                             | SECTIONCONDITION comments expression'''  # noqa: D300, D400, D403, D415

    # Meta elements
    @staticmethod
    def p_meta_kvs(p):
        '''meta_kvs : meta_kvs meta_kv
                    | meta_kvs meta_kv comments
                    | meta_kv comments
                    | meta_kv'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        logger.debug('Matched meta kvs')

    def p_meta_kv(self, p):
        '''meta_kv : ID EQUALS STRING
                   | ID EQUALS ID
                   | ID EQUALS TRUE
                   | ID EQUALS FALSE
                   | ID EQUALS NUM
                   | ID EQUALS HYPHEN NUM'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        key = p[1]
        value = p[3]
        if re.match(r'".*"', value):
            value = p[3].strip('"')
        elif value in ('true', 'false'):
            value = True if value == 'true' else False
        elif value == '-':
            num_value = p[4]
            value = -int(num_value)
        else:
            value = int(value)
        logger.debug(f'Matched meta kv: {key} equals {value}')
        self._add_element(ElementTypes.METADATA_KEY_VALUE, (key, value, ))

    # Strings elements
    @staticmethod
    def p_strings_kvs(p):
        '''strings_kvs : strings_kvs strings_kv
                       | strings_kv'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        logger.debug('Matched strings kvs')

    def _parse_string_kv(self, p, string_type):
        """Perform parsing for all string types.

        Args:
            p: Parser object.
            string_type: StringTypes enum.
        """
        key = p[1]
        value = p[3]
        match = re.match('"(.+)"', value)
        if match:
            value = match.group(1)
        if key != '$' and key in self._stringnames:
            raise ParseTypeError(f'Duplicate string name key {key} on line {p.lineno(1)}', p.lineno, p.lexpos)
        self._stringnames.add(key)
        logger.debug(f'Matched strings kv: {key} equals {value}')
        self._add_element(ElementTypes.STRINGS_KEY_VALUE, (key, value, string_type, ))

    def p_byte_strings_kv(self, p):
        '''strings_kv : STRINGNAME EQUALS BYTESTRING
                      | STRINGNAME EQUALS BYTESTRING comments
                      | STRINGNAME EQUALS BYTESTRING byte_string_modifiers
                      | STRINGNAME EQUALS BYTESTRING byte_string_modifiers comments'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        self._parse_string_kv(p, StringTypes.BYTE)

    def p_text_strings_kv(self, p):
        '''strings_kv : STRINGNAME EQUALS STRING
                      | STRINGNAME EQUALS STRING comments
                      | STRINGNAME EQUALS STRING text_string_modifiers
                      | STRINGNAME EQUALS STRING text_string_modifiers comments'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        self._parse_string_kv(p, StringTypes.TEXT)

    def p_regex_strings_kv(self, p):
        '''strings_kv : STRINGNAME EQUALS REXSTRING
                      | STRINGNAME EQUALS REXSTRING comments
                      | STRINGNAME EQUALS REXSTRING regex_string_modifiers
                      | STRINGNAME EQUALS REXSTRING regex_string_modifiers comments'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        self._parse_string_kv(p, StringTypes.REGEX)

    @staticmethod
    def p_text_string_modifiers(p):
        '''text_string_modifiers : text_string_modifiers text_string_modifier
                                 | text_string_modifier'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    def p_text_string_modifier(self, p):
        '''text_string_modifier : NOCASE
                                | ASCII
                                | WIDE
                                | FULLWORD
                                | XOR_MOD
                                | XOR_MOD xor_mod_args
                                | BASE64
                                | BASE64WIDE
                                | BASE64 base64_with_args
                                | BASE64WIDE base64_with_args
                                | PRIVATE'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        self._add_string_modifier(p)

    @staticmethod
    def p_regex_text_string_modifiers(p):
        '''regex_string_modifiers : regex_string_modifiers regex_string_modifer
                                  | regex_string_modifer'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    def p_regex_string_modifer(self, p):
        '''regex_string_modifer : NOCASE
                                | ASCII
                                | WIDE
                                | FULLWORD
                                | PRIVATE'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        self._add_string_modifier(p)

    @staticmethod
    def p_byte_string_modifiers(p):
        '''byte_string_modifiers : byte_string_modifiers byte_string_modifer
                                 | byte_string_modifer'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    def p_byte_string_modifer(self, p):
        '''byte_string_modifer : PRIVATE'''  # noqa: D300, D400, D403, D415
        self._add_string_modifier(p)

    def p_xor_mod_args(self, p):
        '''xor_mod_args : LPAREN NUM RPAREN
                        | LPAREN NUM HYPHEN NUM RPAREN
                        | LPAREN HEXNUM RPAREN
                        | LPAREN HEXNUM HYPHEN HEXNUM RPAREN
                        | LPAREN NUM HYPHEN HEXNUM RPAREN
                        | LPAREN HEXNUM HYPHEN NUM RPAREN'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        logger.debug('Matched an xor arg: {}'.format(''.join(p[1:])))
        mods = [x for x in p if x not in (None, '(', '-', ')')]
        mod_int_list = []
        mod_lineidx = set()
        for i, x in enumerate(mods):
            mod_int = int(x, 16) if x.startswith('0x') else int(x)
            if 0 <= mod_int <= 255:
                mod_int_list.append(mod_int)
                mod_lineidx.add(i)
            else:
                message = f'String modification value {x} not between 0-255 on line {p.lineno(1 + i)}'
                raise ParseTypeError(message, p.lineno, p.lexpos)
        if mod_int_list[0] > mod_int_list[-1]:
            mod_lineno = list({p.lineno(1 + i) for i in mod_lineidx})
            mod_lineno.sort()
            line_no = ' and '.join(str(lno) for lno in mod_lineno)
            message = f'String modification lower bound exceeds upper bound on line {line_no}'
            raise ParseTypeError(message, p.lineno, p.lexpos)
        else:
            mod_str_mod = YaraXor(mod_int_list)
            logger.debug(f'Matched string modifier(s): {mod_str_mod}')
            self._add_element(ElementTypes.STRINGS_MODIFIER, mod_str_mod)

    def p_base64_with_args(self, p):
        '''base64_with_args : LPAREN STRING RPAREN'''  # noqa: D300, D400, D403, D415
        # Remove parens and leading/trailing quotes
        b64_mod = [x for x in p if x not in (None, '(', ')')][0].strip('"')
        b64_data = b64_mod.encode('ascii').decode('unicode-escape')
        if len(b64_data) != 64:
            raise RuntimeError(f'Base64 dictionary length {len(b64_data)}, must be 64 characters')
        if re.search(r'(.).*\1', b64_data):
            raise RuntimeError('Duplicate character in Base64 dictionary')
        mod_str_mod = YaraBase64(b64_mod)
        logger.debug(f'Matched string modifier(s): {b64_mod}')
        self._add_element(ElementTypes.STRINGS_MODIFIER, mod_str_mod)

    def p_comments(self, p):
        '''comments : COMMENT
                    | MCOMMENT'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        logger.debug(f'Matched a comment: {p[1]}')

        if p[1][:2] == '//':
            self._add_element(ElementTypes.COMMENT, p[1])
        else:
            self._add_element(ElementTypes.MCOMMENT, p[1])

    # Condition elements
    @staticmethod
    def p_expression(p):
        '''expression : expression term
                      | expression term comments
                      | term
                      | term comments'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415

    def p_condition(self, p):
        '''term : FILESIZE_SIZE
                | ID
                | NUM
                | HEXNUM
                | STRING
                | LPAREN
                | RPAREN
                | LBRACK
                | RBRACK
                | DOTDOT
                | EQUIVALENT
                | EQUALS
                | NEQUALS
                | PLUS
                | PIPE
                | BACKSLASH
                | COMMA
                | GREATERTHAN
                | LESSTHAN
                | GREATEREQUAL
                | LESSEQUAL
                | RIGHTBITSHIFT
                | LEFTBITSHIFT
                | MODULO
                | TILDE
                | XOR_OP
                | PERIOD
                | COLON
                | STAR
                | HYPHEN
                | AMPERSAND
                | ALL
                | AND
                | ANY
                | AT
                | CONTAINS
                | DEFINED
                | ENTRYPOINT
                | FALSE
                | FILESIZE
                | FOR
                | IN
                | INT8
                | INT16
                | INT32
                | INT8BE
                | INT16BE
                | INT32BE
                | MATCHES
                | NONE
                | NOT
                | OR
                | OF
                | THEM
                | TRUE
                | UINT8
                | UINT16
                | UINT32
                | UINT8BE
                | UINT16BE
                | UINT32BE
                | STRINGNAME
                | STRINGNAME_ARRAY
                | STRINGNAME_LENGTH
                | STRINGNAME_COUNT
                | REXSTRING
                | ICONTAINS
                | ENDSWITH
                | IENDSWITH
                | STARTSWITH
                | ISTARTSWITH
                | IEQUALS'''  # noqa: D205, D208, D209, D300, D400, D401, D403, D415
        logger.debug(f'Matched a condition term: {p[1]}')
        if p[1] == '$':
            logger.info(f'Potential wrong use of anonymous string on line {p.lineno(1)}')

        self._add_element(ElementTypes.TERM, p[1])

    # Error rule for syntax errors
    def p_error(self, p):
        """Raise syntax errors.

        Args:
            p: Data from the parser.

        Raises:
            ParseTypeError
        """
        if not p:
            # This happens when we try to parse an empty string or file, or one with no actual rules.
            pass
        elif p.type in ('COMMENT', 'MCOMMENT'):  # Only bytestring internal comments should fall through to here
            self.parser.errok()  # This is a method from PLY to reset the error state from parsing a comment
            self._rule_comments.append(p)
        else:
            message = f'Unknown text {p.value} for token of type {p.type} on line {p.lineno}'
            raise ParseTypeError(message, p.lineno, p.lexpos)

    @staticmethod
    def _process_string_with_escapes(t, escape_chars=None):
        if escape_chars is None:
            escape_chars = [t.value]
        if t.lexer.escape == 1 and t.value in escape_chars or t.value == '\\':
            t.lexer.escape ^= 1
            if t.value == 'x':
                t.lexer.hex_escape = 2
        elif t.lexer.hex_escape > 0:
            if t.value.lower() in string.hexdigits:
                t.lexer.hex_escape -= 1
            else:
                raise ParseTypeError(f'Invalid hex character: {t.value!r}, at line: {t.lexer.lineno}',
                                     t.lexer.lineno, t.lexer.lexpos)
        elif t.lexer.escape == 1:
            raise ParseTypeError(f'Invalid escape sequence: \\{t.value}, at line: {t.lexer.lineno}',
                                 t.lexer.lineno, t.lexer.lexpos)

    def _add_string_modifier(self, p):
        mod_str = p[1]
        prev_mod_with_args = False
        if mod_str in self.string_modifiers:
            raise ParseTypeError(f'Duplicate string modifier {mod_str} on line {p.lineno(1)}', p.lineno, p.lexpos)
        if mod_str in self.EXCLUSIVE_TEXT_MODIFIERS:
            prev_mods = {x for x in self.string_modifiers if isinstance(x, str)}
            excluded_modifiers = prev_mods & ({mod_str} ^ self.EXCLUSIVE_TEXT_MODIFIERS)
            if excluded_modifiers:
                pr_mod_str = excluded_modifiers.pop()
                msg = f'Mutually exclusive string modifier use: {mod_str}, line {p.lineno(1)}, after {pr_mod_str} usage'
                raise ParseTypeError(msg, p.lineno, p.lexpos)
        if self.string_modifiers:
            # Convert previously created modifiers with args to strings
            if mod_str.startswith('base64') and isinstance(self.string_modifiers[-1], YaraBase64):
                if mod_str == 'base64wide':
                    self.string_modifiers[-1].modifier_name = 'base64wide'
                    logger.debug('Corrected base64 string modifier to base64wide')
                self.string_modifiers[-1] = str(self.string_modifiers[-1])
                prev_mod_with_args = True
            elif mod_str == 'xor' and isinstance(self.string_modifiers[-1], YaraXor):
                self.string_modifiers[-1] = str(self.string_modifiers[-1])
                logger.debug('Modified xor string was already added')
                prev_mod_with_args = True
        if not prev_mod_with_args:
            self._add_element(ElementTypes.STRINGS_MODIFIER, mod_str)
            logger.debug(f'Matched a string modifier: {mod_str}')


class YaraXor(str):
    """YARA xor string modifier."""

    def __init__(self, xor_range=None):
        """Initialize XOR string modifier."""
        str.__init__(self)
        self.modifier_name = 'xor'
        self.modifier_list = xor_range if xor_range is not None else []

    def __str__(self):
        """Return the string representation."""
        if len(self.modifier_list) == 0:
            return self.modifier_name
        return '{}({})'.format(
            self.modifier_name,
            '-'.join(['{0:#0{1}x}'.format(x, 4) for x in self.modifier_list])
        )

    def __repr__(self):
        """Return the object representation."""
        if len(self.modifier_list) == 0:
            return '{}()'.format(self.__class__.__name__)
        else:
            return '{}({})'.format(self.__class__.__name__, self.modifier_list)


class YaraBase64(str):
    """YARA base64 string modifier for easier printing."""

    def __init__(self, modifier_alphabet=None, modifier_name='base64'):
        """Initialize base64 string modifier."""
        str.__init__(self)
        self.modifier_name = 'base64' if modifier_name != 'base64wide' else 'base64wide'
        self.modifier_alphabet = modifier_alphabet

    def __str__(self):
        """Return the string representation."""
        if self.modifier_alphabet is None:
            return '{}'.format(self.modifier_name)
        else:
            return '{}("{}")'.format(self.modifier_name, self.modifier_alphabet)

    def __repr__(self):
        """Return the object representation."""
        if self.modifier_alphabet is None:
            return '{}()'.format(self.__class__.__name__)
        else:
            return '{}({})'.format(self.__class__.__name__, repr(self.modifier_alphabet))
