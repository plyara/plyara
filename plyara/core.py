#!/usr/bin/env python
# Copyright 2014 Christian Buia
# Copyright 2019 plyara Maintainers
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
import distutils.util
import enum
import logging
import tempfile
import re

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

    COMPARISON_OPERATORS = ('==', '!=', '>', '<', '>=', '<=', )

    IMPORT_OPTIONS = ('pe',
                      'elf',
                      'cuckoo',
                      'magic',
                      'hash',
                      'math',
                      'dotnet',
                      'androguard', )

    KEYWORDS = ('all', 'and', 'any', 'ascii', 'at', 'condition',
                'contains', 'entrypoint', 'false', 'filesize',
                'fullword', 'for', 'global', 'in', 'import',
                'include', 'int8', 'int16', 'int32', 'int8be',
                'int16be', 'int32be', 'matches', 'meta', 'nocase',
                'not', 'or', 'of', 'private', 'rule', 'strings',
                'them', 'true', 'uint8', 'uint16', 'uint32', 'uint8be',
                'uint16be', 'uint32be', 'wide', 'xor', )

    FUNCTION_KEYWORDS = ('uint8', 'uint16', 'uint32', 'uint8be', 'uint16be', 'uint32be', )

    def __init__(self, console_logging=False, store_raw_sections=True):
        """Initialize the parser object.

        Args:
            console_logging: Enable a stream handler if no handlers exist. (default False)
            store_raw_sections: Enable attribute storage of raw section input. (default True)
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

        if console_logging:
            self._set_logging()

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

        self.lexer = lex.lex(module=self, debug=False)
        self.parser = yacc.yacc(module=self, debug=False, outputdir=tempfile.gettempdir())

    @staticmethod
    def _set_logging():
        """Set the console logger only if handler(s) aren't already set."""
        if not len(logger.handlers):
            logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            logger.addHandler(ch)

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

        elif element_type == ElementTypes.METADATA_KEY_VALUE:
            key, value = element_value

            if 'metadata' not in self.current_rule:
                self.current_rule['metadata'] = [{key: value}]
            else:
                self.current_rule['metadata'].append({key: value})

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

        elif element_type == ElementTypes.MCOMMENT:
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

    def parse_string(self, input_string):
        """Take a string input expected to consist of YARA rules, and return list of dictionaries representing them.

        Args:
            input_string: String input expected to consist of YARA rules.

        Returns:
            dict: All the parsed components of a YARA rule.
        """
        self._raw_input = input_string
        yacc.parse(input_string)

        for rule in self.rules:
            if any(self.imports):
                rule['imports'] = list(self.imports)
            if any(self.includes):
                rule['includes'] = self.includes

        return self.rules

    @staticmethod
    def is_valid_rule_name(entry):
        """Validate rule name: DEPRECATED."""
        from plyara.utils import is_valid_rule_name
        import warnings
        warnings.warn('Static method is_valid_rule_name() is deprecated: use plyara.utils', DeprecationWarning)
        return is_valid_rule_name(entry)

    @staticmethod
    def is_valid_rule_tag(entry):
        """Validate tag: DEPRECATED."""
        from plyara.utils import is_valid_rule_tag
        import warnings
        warnings.warn('Static method is_valid_rule_tag() is deprecated: use plyara.utils', DeprecationWarning)
        return is_valid_rule_tag(entry)

    @staticmethod
    def detect_imports(rule):
        """Detect imports: DEPRECATED."""
        from plyara.utils import detect_imports
        import warnings
        warnings.warn('Static method detect_imports() is deprecated: use plyara.utils', DeprecationWarning)
        return detect_imports(rule)

    @staticmethod
    def detect_dependencies(rule):
        """Detect dependencies: DEPRECATED."""
        from plyara.utils import detect_dependencies
        import warnings
        warnings.warn('Static method detect_dependencies() is deprecated: use plyara.utils', DeprecationWarning)
        return detect_dependencies(rule)

    @staticmethod
    def generate_logic_hash(rule):
        """Generate logic hash: DEPRECATED."""
        from plyara.utils import generate_logic_hash
        import warnings
        warnings.warn('Static method generate_logic_hash() is deprecated: use plyara.utils', DeprecationWarning)
        return generate_logic_hash(rule)

    @staticmethod
    def rebuild_yara_rule(rule):
        """Rebuild rule: DEPRECATED."""
        from plyara.utils import rebuild_yara_rule
        import warnings
        warnings.warn('Static method rebuild_yara_rule() is deprecated: use plyara.utils', DeprecationWarning)
        return rebuild_yara_rule(rule)


class Plyara(Parser):
    """Define the lexer and the parser rules."""

    tokens = [
        'BYTESTRING',
        'STRING',
        'REXSTRING',
        'EQUALS',
        'STRINGNAME',
        'STRINGNAME_ARRAY',
        'STRINGNAME_LENGTH',
        'LPAREN',
        'RPAREN',
        'LBRACK',
        'RBRACK',
        'LBRACE',
        'RBRACE',
        'ID',
        'BACKSLASH',
        'FORWARDSLASH',
        'PIPE',
        'PLUS',
        'SECTIONMETA',
        'SECTIONSTRINGS',
        'SECTIONCONDITION',
        'COMMA',
        'STRINGCOUNT',
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
        'xor': 'XOR_MOD'  # XOR string modifier token (from strings section)
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
    t_FORWARDSLASH = r'/'
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
        r'}'
        t.value = t.value
        self._condition_end = t.lexpos

        return t

    def t_NEWLINE(self, t):
        r'(\n|\r|\r\n)+'
        t.lexer.lineno += len(t.value)
        t.value = t.value

    def t_COMMENT(self, t):
        r'(//.*)(?=\n)'
        return t

    def t_MCOMMENT(self, t):
        r'/\*(.|\n|\r\n)*?\*/'
        if '\r\n' in t.value:
            t.lexer.lineno += t.value.count('\r\n')
        else:
            t.lexer.lineno += t.value.count('\n')

        return t

    def t_HEXNUM(self, t):
        r'0x[A-Fa-f0-9]+'
        t.value = t.value

        return t

    def t_SECTIONMETA(self, t):
        r'meta\s*:'
        t.value = t.value
        self._meta_start = t.lexpos
        t.lexer.section = 'meta'

        return t

    def t_SECTIONSTRINGS(self, t):
        r'strings\s*:'
        t.value = t.value
        self._strings_start = t.lexpos
        if self._meta_end is None:
            self._meta_end = t.lexpos
        t.lexer.section = 'strings'

        return t

    def t_SECTIONCONDITION(self, t):
        r'condition\s*:'
        t.value = t.value
        self._condition_start = t.lexpos
        if self._meta_end is None:
            self._meta_end = t.lexpos
        if self._strings_end is None:
            self._strings_end = t.lexpos
        t.lexer.section = 'condition'

        return t

    # Text string handling
    def t_begin_STRING(self, t):
        r'"'
        t.lexer.escape = 0
        t.lexer.string_start = t.lexer.lexpos - 1
        t.lexer.begin('STRING')

    def t_STRING_value(self, t):
        r'.'
        if t.lexer.escape == 0 and t.value == '"':
            t.type = 'STRING'
            t.value = t.lexer.lexdata[t.lexer.string_start:t.lexer.lexpos]
            t.lexer.begin('INITIAL')

            return t

        if t.value == '\\' or t.lexer.escape == 1:
            t.lexer.escape ^= 1

    t_STRING_ignore = ' \t\n'

    def t_STRING_error(self, t):
        """Raise parsing error for illegal string character.

        Args:
            t: Token input from lexer.

        Raises:
            ParseTypeError
        """
        raise ParseTypeError('Illegal string character: {}, at line: {}'.format(t.value[0], t.lexer.lineno),
                             t.lexer.lineno, t.lexer.lexpos)

    # Byte string handling
    def t_begin_BYTESTRING(self, t):
        r'\{'
        if hasattr(t.lexer, 'section') and t.lexer.section == 'strings':
            t.lexer.bytestring_start = t.lexer.lexpos - 1
            t.lexer.begin('BYTESTRING')
            t.lexer.bytestring_group = 0
        else:
            t.type = 'LBRACE'

            return t

    def t_BYTESTRING_pair(self, t):
        r'\s*[a-fA-F0-9?]{2}\s*'

    def t_BYTESTRING_comment(self, t):
        r'\/\/[^\r\n]*'

    def t_BYTESTRING_mcomment(self, t):
        r'/\*(.|\n|\r\n)*?\*/'

    def t_BYTESTRING_jump(self, t):
        r'\[\s*(\d*)\s*-?\s*(\d*)\s*\]'
        groups = t.lexer.lexmatch.groups()
        index = groups.index(t.value)

        lower_bound = groups[index + 1]
        upper_bound = groups[index + 2]

        if lower_bound and upper_bound:
            if not 0 <= int(lower_bound) <= int(upper_bound):
                raise ParseValueError('Illegal bytestring jump bounds: {}, at line: {}'.format(t.value, t.lexer.lineno),
                                      t.lexer.lineno, t.lexer.lexpos)

    def t_BYTESTRING_group_start(self, t):
        r'\('
        t.lexer.bytestring_group += 1

    def t_BYTESTRING_group_end(self, t):
        r'\)'
        t.lexer.bytestring_group -= 1

    def t_BYTESTRING_group_logical_or(self, t):
        r'\|'

    def t_BYTESTRING_end(self, t):
        r'\}'
        t.type = 'BYTESTRING'
        t.value = t.lexer.lexdata[t.lexer.bytestring_start:t.lexer.lexpos]

        if t.lexer.bytestring_group != 0:
            raise ParseValueError('Unbalanced group in bytestring: {}, at line: {}'.format(t.value, t.lexer.lineno),
                                  t.lexer.lineno, t.lexer.lexpos)

        t.lexer.begin('INITIAL')

        # Account for newlines in bytestring.
        if '\r\n' in t.value:
            t.lexer.lineno += t.value.count('\r\n')
        else:
            t.lexer.lineno += t.value.count('\n')

        return t

    t_BYTESTRING_ignore = ' \r\n\t'

    def t_BYTESTRING_error(self, t):
        """Raise parsing error for illegal bytestring character.

        Args:
            t: Token input from lexer.

        Raises:
            ParseTypeError
        """
        raise ParseTypeError('Illegal bytestring character : {}, at line: {}'.format(t.value[0], t.lexer.lineno),
                             t.lexer.lineno, t.lexer.lexpos)

    # Rexstring Handling
    def t_begin_REXSTRING(self, t):
        r'/'
        if hasattr(t.lexer, 'section') and t.lexer.section in ('strings', 'condition'):
            t.lexer.rexstring_start = t.lexer.lexpos - 1
            t.lexer.begin('REXSTRING')
            t.lexer.escape = 0
        else:
            t.type = 'FORWARDSLASH'

            return t

    def t_REXSTRING_end(self, t):
        r'/(?:[ismx]*)'
        if t.lexer.escape == 0:
            t.type = 'REXSTRING'
            t.value = t.lexer.lexdata[t.lexer.rexstring_start:t.lexer.lexpos]
            t.lexer.begin('INITIAL')

            return t
        else:
            t.lexer.escape ^= 1

    def t_REXSTRING_value(self, t):
        r'.'
        if t.value == '\\' or t.lexer.escape == 1:
            t.lexer.escape ^= 1

    t_REXSTRING_ignore = ' \r\n\t'

    def t_REXSTRING_error(self, t):
        """Raise parsing error for illegal rexstring character.

        Args:
            t: Token input from lexer.

        Raises:
            ParseTypeError
        """
        raise ParseTypeError('Illegal rexstring character : {}, at line: {}'.format(t.value[0], t.lexer.lineno),
                             t.lexer.lineno, t.lexer.lexpos)

    def t_STRINGNAME(self, t):
        r'\$[0-9a-zA-Z\-_*]*'
        t.value = t.value

        return t

    def t_STRINGNAME_ARRAY(self, t):
        r'@[0-9a-zA-Z\-_*]*'
        t.value = t.value

        return t

    def t_STRINGNAME_LENGTH(self, t):
        r'![0-9a-zA-Z\-_*]+'
        t.value = t.value

        return t

    def t_FILESIZE_SIZE(self, t):
        r"\d+[KM]B"
        t.value = t.value

        return t

    def t_NUM(self, t):
        r'\d+(\.\d+)?|0x\d+'
        t.value = t.value

        return t

    def t_ID(self, t):
        r'[a-zA-Z_]{1}[a-zA-Z_0-9.]*'
        t.type = self.reserved.get(t.value, 'ID')  # Check for reserved words

        return t

    def t_STRINGCOUNT(self, t):
        r'\#[^\s]*'
        t.value = t.value

        return t

    # A string containing ignored characters (spaces and tabs)
    t_ignore = ' \t'

    # Error handling rule
    def t_error(self, t):
        """Raise parsing error.

        Args:
            t: Token input from lexer.

        Raises:
            ParseTypeError
        """
        raise ParseTypeError('Illegal character {} at line {}'.format(t.value[0], t.lexer.lineno),
                             t.lexer.lineno, t.lexer.lexpos)

    # Parsing rules
    precedence = (
        ('right', 'NUM', ),
        ('right', 'ID', ),
        ('right', 'HEXNUM', )
    )

    def p_ruleset(self, p):
        '''ruleset : rules
                   | imports
                   | includes
                   | ruleset ruleset'''

    def p_rules(self, p):
        '''rules : rules rule
                 | rule'''

    def p_rule(self, p):
        '''rule : scopes RULE ID tag_section LBRACE rule_body RBRACE'''
        logger.info('Matched rule: {}'.format(p[3]))
        logger.debug('Rule start: {}, Rule stop: {}'.format(p.lineno(2), p.lineno(7)))

        while self._rule_comments:
            comment = self._rule_comments.pop()

            if p.lexpos(5) < comment.lexpos < p.lexpos(7):
                self._add_element(getattr(ElementTypes, comment.type), comment.value)

        element_value = (p[3], int(p.lineno(2)), int(p.lineno(7)), )
        self._add_element(ElementTypes.RULE_NAME, element_value)

    def p_imports(self, p):
        '''imports : imports import
                   | import'''

    def p_includes(self, p):
        '''includes : includes include
                    | include'''

    def p_scopes(self, p):
        '''scopes : scopes scope
                  | scope
                  | '''

    def p_import(self, p):
        '''import : IMPORT STRING'''
        import_value = p[2].replace('"', '')
        logger.debug('Matched import: {}'.format(import_value))
        self._add_element(ElementTypes.IMPORT, import_value)

    def p_include(self, p):
        '''include : INCLUDE STRING'''
        include_value = p[2].replace('"', '')
        logger.debug('Matched include: {}'.format(include_value))
        self._add_element(ElementTypes.INCLUDE, include_value)

    def p_scope(self, p):
        '''scope : PRIVATE
                 | GLOBAL'''
        logger.debug('Matched scope identifier: {}'.format(p[1]))
        self._add_element(ElementTypes.SCOPE, p[1])

    def p_tag_section(self, p):
        '''tag_section : COLON tags
                       | '''

    def p_tags(self, p):
        '''tags : tags tag
                | tag'''

    def p_tag(self, p):
        '''tag : ID'''
        logger.debug('Matched tag: {}'.format(p[1]))
        self._add_element(ElementTypes.TAG, p[1])

    def p_rule_body(self, p):
        '''rule_body : sections'''
        logger.info('Matched rule body')

    def p_rule_sections(self, p):
        '''sections : sections section
                    | section'''

    def p_rule_section(self, p):
        '''section : meta_section
                   | strings_section
                   | condition_section'''

    def p_meta_section(self, p):
        '''meta_section : SECTIONMETA meta_kvs'''
        logger.info('Matched meta section')

    def p_strings_section(self, p):
        '''strings_section : SECTIONSTRINGS strings_kvs'''

    def p_condition_section(self, p):
        '''condition_section : SECTIONCONDITION expression'''

    # Meta elements
    def p_meta_kvs(self, p):
        '''meta_kvs : meta_kvs meta_kv
                    | meta_kv'''
        logger.info('Matched meta kvs')

    def p_meta_kv(self, p):
        '''meta_kv : ID EQUALS STRING
                   | ID EQUALS ID
                   | ID EQUALS TRUE
                   | ID EQUALS FALSE
                   | ID EQUALS NUM'''
        key = p[1]
        value = p[3]
        if re.match(r'".*"', value):
            match = re.match('"(.*)"', value)
            if match:
                value = match.group(1)
        elif value == 'true' or value == 'false':
            value = bool(distutils.util.strtobool(value))
        else:
            value = int(value)
        logger.debug('Matched meta kv: {} equals {}'.format(key, value))
        self._add_element(ElementTypes.METADATA_KEY_VALUE, (key, value, ))

    # Strings elements
    def p_strings_kvs(self, p):
        '''strings_kvs : strings_kvs strings_kv
                       | strings_kv'''
        logger.info('Matched strings kvs')

    def _parse_string_kv(self, p, string_type):
        """Perform parsing for all string types.

        Args:
            p: Parser object.
        """
        key = p[1]
        value = p[3]
        match = re.match('"(.+)"', value)
        if match:
            value = match.group(1)
        logger.debug('Matched strings kv: {} equals {}'.format(key, value))
        self._add_element(ElementTypes.STRINGS_KEY_VALUE, (key, value, string_type, ))

    def p_text_strings_kv(self, p):
        '''strings_kv : STRINGNAME EQUALS STRING
                      | STRINGNAME EQUALS STRING string_modifiers'''
        self._parse_string_kv(p, StringTypes.TEXT)

    def p_byte_strings_kv(self, p):
        '''strings_kv : STRINGNAME EQUALS BYTESTRING'''
        self._parse_string_kv(p, StringTypes.BYTE)

    def p_regex_strings_kv(self, p):
        '''strings_kv : STRINGNAME EQUALS REXSTRING
                      | STRINGNAME EQUALS REXSTRING comments
                      | STRINGNAME EQUALS REXSTRING string_modifiers
                      | STRINGNAME EQUALS REXSTRING string_modifiers comments'''
        self._parse_string_kv(p, StringTypes.REGEX)

    def p_string_modifers(self, p):
        '''string_modifiers : string_modifiers string_modifier
                            | string_modifier'''

    def p_string_modifier(self, p):
        '''string_modifier : NOCASE
                           | ASCII
                           | WIDE
                           | FULLWORD
                           | XOR_MOD'''
        logger.debug('Matched a string modifier: {}'.format(p[1]))
        self._add_element(ElementTypes.STRINGS_MODIFIER, p[1])

    def p_comments(self, p):
        '''comments : COMMENT
                    | MCOMMENT'''
        logger.debug('Matched a comment: {}'.format(p[1]))

    # Condition elements
    def p_expression(self, p):
        '''expression : expression term
                      | term'''

    def p_condition(self, p):
        '''term : FILESIZE_SIZE
                | ID
                | STRING
                | NUM
                | HEXNUM
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
                | FORWARDSLASH
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
                | STRINGCOUNT
                | REXSTRING'''
        logger.debug('Matched a condition term: {}'.format(p[1]))
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
        elif p.type in ('COMMENT', 'MCOMMENT'):
            self.parser.errok()  # This is a method from PLY to reset the error state from parsing a comment
            self._rule_comments.append(p)
        else:
            message = 'Unknown text {} for token of type {} on line {}'.format(p.value, p.type, p.lineno)
            raise ParseTypeError(message, p.lineno, p.lexpos)
