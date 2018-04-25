import argparse
import enum
import json
import logging

import ply.lex as lex
import ply.yacc as yacc

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


class Parser:
    """Interpret the output of the parser and produce an alternative representation of Yara rules."""

    def __init__(self, console_logging=False, store_raw_sections=True):
        """Initialize the parser object.

            Args:
                console_logging: enable a stream handler if no handlers exist (default False)
                store_raw_sections: enable attribute storage of raw section input
        """
        self.rules = list()

        self.current_rule = dict()

        self.string_modifiers = list()
        self.imports = list()
        self.includes = list()
        self.terms = list()
        self.scopes = list()
        self.tags = list()

        if console_logging:
            self._set_logging()

        # adds functionality to track attributes containing raw section data
        # in case needed (ie modifying metadata and re-constructing a complete rule
        # while maintaining original comments and padding)
        self.store_raw_sections = store_raw_sections
        self._meta_start = None
        self._meta_end = None
        self._strings_start = None
        self._strings_end = None
        self._condition_start = None
        self._condition_end = None

        lex.lex(module=self, debug=False)
        yacc.yacc(module=self, debug=False, outputdir='/tmp')

    @staticmethod
    def _set_logging():
        """Set the console logger only if handler(s) aren't already set"""
        if not len(logger.handlers):
            logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            logger.addHandler(ch)

    def _add_element(self, element_type, element_value):
        """Accept elements from the parser and uses them to construct a representation of the Yara rule."""
        if element_type == ElementTypes.RULE_NAME:
            rule_name, start_line, stop_line = element_value
            self.current_rule['rule_name'] = rule_name
            self.current_rule['start_line'] = start_line
            self.current_rule['stop_line'] = stop_line

            if self.store_raw_sections:
                if self._meta_start:
                    self.current_rule['raw_meta'] = self.raw_input[self._meta_start:self._meta_end]

                if self._strings_start:
                    self.current_rule['raw_strings'] = self.raw_input[self._strings_start:self._strings_end]

                if self._condition_start:
                    self.current_rule['raw_condition'] = self.raw_input[self._condition_start:self._condition_end]

            self._flush_accumulators()

            self.rules.append(self.current_rule)
            logger.debug('Adding Rule: {}'.format(self.current_rule['rule_name']))
            self.current_rule = dict()

        elif element_type == ElementTypes.METADATA_KEY_VALUE:
            key, value = element_value

            if 'metadata' not in self.current_rule:
                self.current_rule['metadata'] = {key: value}
            else:
                if key not in self.current_rule['metadata']:
                    self.current_rule['metadata'][key] = value
                else:
                    if isinstance(self.current_rule['metadata'][key], list):
                        self.current_rule['metadata'][key].append(value)
                    else:
                        kv_list = [self.current_rule['metadata'][key], value]
                        self.current_rule['metadata'][key] = kv_list

        elif element_type == ElementTypes.STRINGS_KEY_VALUE:
            key, value = element_value

            string_dict = {'name': key, 'value': value}

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
            self.imports.append(element_value)

        elif element_type == ElementTypes.INCLUDE:
            self.includes.append(element_value)

        elif element_type == ElementTypes.TERM:
            self.terms.append(element_value)

        elif element_type == ElementTypes.SCOPE:
            self.scopes.append(element_value)

        elif element_type == ElementTypes.TAG:
            self.tags.append(element_value)

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

        self._meta_start = None
        self._meta_end = None
        self._strings_start = None
        self._strings_end = None
        self._condition_start = None
        self._condition_end = None

    def parse_string(self, input_string):
        """Take a string input expected to consist of Yara rules, and return list of dictionaries representing them."""
        self.raw_input = input_string
        yacc.parse(input_string)

        for rule in self.rules:
            if any(self.imports):
                rule['imports'] = self.imports
            if any(self.includes):
                rule['includes'] = self.includes

        return self.rules


class Plyara(Parser):
    """Class to define the lexer and the parser rules."""

    tokens = [
        'BYTESTRING',
        'STRING',
        'REXSTRING',
        'EQUALS',
        'STRINGNAME',
        'STRINGNAME_ARRAY',
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
        'XOR',
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
    t_XOR = r'\^'
    t_PERIOD = r'\.'
    t_COLON = r':'
    t_STAR = r'\*'
    t_LBRACK = r'\['
    t_RBRACK = r'\]'
    t_HYPHEN = r'\-'
    t_AMPERSAND = r'&'
    t_DOTDOT = r'\.\.'

    def t_RBRACE(self, t):
        r'}'
        t.value = t.value
        self._condition_end = t.lexpos - 1
        return t

    def t_NEWLINE(self, t):
        # r'\n+'
        r'(\n|\r\n)+'
        t.lexer.lineno += len(t.value)
        t.value = t.value
        pass

    def t_COMMENT(self, t):
        r'(//.*)(?=\n)'
        pass

    # http://comments.gmane.org/gmane.comp.python.ply/134
    def t_MCOMMENT(self, t):
        # r'/\*(.|\n)*?\*/'
        r'/\*(.|\n|\r\n)*?\*/'
        if '\r\n' in t.value:
            t.lexer.lineno += t.value.count('\r\n')
        else:
            t.lexer.lineno += t.value.count('\n')
        pass

    def t_HEXNUM(self, t):
        r'0x[A-Fa-f0-9]+'
        t.value = t.value
        return t

    def t_SECTIONMETA(self, t):
        r'meta:'
        t.value = t.value
        self._meta_start = t.lexpos
        return t

    def t_SECTIONSTRINGS(self, t):
        r'strings:'
        t.value = t.value
        self._strings_start = t.lexpos
        if self._meta_end is None:
            self._meta_end = t.lexpos - 1
        return t

    def t_SECTIONCONDITION(self, t):
        r'condition:'
        t.value = t.value
        self._condition_start = t.lexpos
        if self._meta_end is None:
            self._meta_end = t.lexpos - 1
        if self._strings_end is None:
            self._strings_end = t.lexpos - 1
        return t

    def t_STRING(self, t):
        r"(?P<openingQuote>[\"'])(?:(?=(?P<escaped>\\?))(?P=escaped).)*?(?P=openingQuote)"
        t.value = t.value
        return t

    def t_BYTESTRING(self, t):
        r'\{\s*(?:(?:[a-fA-F0-9?]{2}|\[\d*-?\d*\]|\((?:\s*[a-fA-F0-9?]{2}\s*\|?\s*|\s*\[\d*-?\d*\]\s*)+\)|\/\/[^\n]*)\s*)+\s*\}'
        """
        Regex above broken down broken down
        remove all literal spaces below, just there to visualize and piece together.

        \{\s*                                                              // start
          (?:                                                              // open for combinations of...
            (?:[a-fA-F0-9?]{2}                                          |  // byte pair
               \[\d*-?\d*\]                                             |  // jump
               \((?:\s*[a-fA-F0-9?]{2}\s*\|?\s*|\s*\[\d*-?\d*\]\s*)+\)  |  // group
               \/\/[^\n]*                                                  // comment
          )\s*)+                                                           // close combinations
        \s*\}                                                              // close bytestring
        """
        t.value = t.value
        return t

    def t_REXSTRING(self, t):
        r'(\/.+(?:\/[ismx]*)(?=\s+(?:nocase|ascii|wide|fullword)?\s*\/))|(\/.+(?:\/[ismx]*)(?=\s|\)|$))'
        """
        Two parts to this regex, because I'm not sure how to simplify. Test against following cases...
        /abc123 \d/i
        /abc123 \d+/i // comment
        /abc123 \d\/ afterspace/im // comment
        /abc123 \d\/ afterspace/im nocase // comment

        (\/.+(?:\/[ismx]*)(?=\s+(?:nocase|ascii|wide|fullword)?\s*\/))  | first half matches `/abc123/im // comment` format
        (\/.+(?:\/[ismx]*)(?=\s|\)|$))                                    second half matches `/abc123/im` format

        It should only consume the regex pattern and not text modifiers / comment, as those will be parsed separately
        """

        t.value = t.value
        return t

    def t_STRINGNAME(self, t):
        r'\$[0-9a-zA-Z\-_*]*'
        t.value = t.value
        return t

    def t_STRINGNAME_ARRAY(self, t):
        r'@[0-9a-zA-Z\-_*]*'
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
    # t_ignore = ' \t\r\n'
    t_ignore = ' \t'

    # Error handling rule
    def t_error(self, t):
        raise TypeError('Illegal character {} at line {}'.format(t.value[0], str(t.lexer.lineno)))
        t.lexer.skip(1)

    # Parsing rules

    precedence = (('right', 'NUM'), ('right', 'ID'), ('right', 'HEXNUM'))

    def p_rules(self, p):
        '''rules : rules rule
                 | rule'''

    def p_rule(self, p):
        '''rule : imports_and_scopes RULE ID tag_section LBRACE rule_body RBRACE'''

        logger.debug('Matched rule: {}'.format(str(p[3])))
        logger.debug('Rule start: {}, Rule stop: {}'.format(p.lineno(2), p.lineno(7)))
        element_value = (str(p[3]), int(p.lineno(2)), int(p.lineno(7)), )
        self._add_element(ElementTypes.RULE_NAME, element_value)

    def p_imports_and_scopes(self, p):
        '''imports_and_scopes : imports
                              | includes
                              | scopes
                              | imports scopes
                              | includes scopes
                              | '''

    def p_imports(self, p):
        '''imports : imports import
                   | includes
                   | import'''

    def p_includes(self, p):
        '''includes : includes include
                    | imports
                    | include'''

    def p_import(self, p):
        'import : IMPORT STRING'
        logger.debug('Matched import: {}'.format(p[2]))
        self._add_element(ElementTypes.IMPORT, p[2])

    def p_include(self, p):
        'include : INCLUDE STRING'
        logger.debug('Matched include: {}'.format(p[2]))
        self._add_element(ElementTypes.INCLUDE, p[2])

    def p_scopes(self, p):
        '''scopes : scopes scope
                  | scope'''

    def p_tag_section(self, p):
        '''tag_section : COLON tags
                       | '''

    def p_tags(self, p):
        '''tags : tags tag
                | tag'''

    def p_tag(self, p):
        'tag : ID'
        logger.debug('Matched tag: {}'.format(str(p[1])))
        self._add_element(ElementTypes.TAG, p[1])

    def p_scope(self, p):
        '''scope : PRIVATE
                 | GLOBAL'''
        logger.debug('Matched scope identifier: {}'.format(str(p[1])))
        self._add_element(ElementTypes.SCOPE, p[1])

    def p_rule_body(self, p):
        'rule_body : sections'
        logger.debug('Matched rule body')

    def p_rule_sections(self, p):
        '''sections : sections section
                    | section'''

    def p_rule_section(self, p):
        '''section : meta_section
                   | strings_section
                   | condition_section'''

    def p_meta_section(self, p):
        'meta_section : SECTIONMETA meta_kvs'
        logger.debug('Matched meta section')

    def p_strings_section(self, p):
        'strings_section : SECTIONSTRINGS strings_kvs'

    def p_condition_section(self, p):
        '''condition_section : SECTIONCONDITION expression'''

    # Meta elements.
    def p_meta_kvs(self, p):
        '''meta_kvs : meta_kvs meta_kv
                    | meta_kv'''
        logger.debug('Matched meta kvs')

    def p_meta_kv(self, p):
        '''meta_kv : ID EQUALS STRING
                   | ID EQUALS ID
                   | ID EQUALS TRUE
                   | ID EQUALS FALSE
                   | ID EQUALS NUM'''
        key = str(p[1])
        value = str(p[3]).strip('"')
        logger.debug('Matched meta kv: {} equals {}'.format(key, value))
        self._add_element(ElementTypes.METADATA_KEY_VALUE, (key, value, ))

    # Strings elements.
    def p_strings_kvs(self, p):
        '''strings_kvs : strings_kvs strings_kv
                       | strings_kv'''
        logger.debug('Matched strings kvs')

    def p_strings_kv(self, p):
        '''strings_kv : STRINGNAME EQUALS STRING
                      | STRINGNAME EQUALS STRING string_modifiers
                      | STRINGNAME EQUALS BYTESTRING
                      | STRINGNAME EQUALS REXSTRING
                      | STRINGNAME EQUALS REXSTRING comments
                      | STRINGNAME EQUALS REXSTRING string_modifiers
                      | STRINGNAME EQUALS REXSTRING string_modifiers comments'''

        key = str(p[1])
        value = str(p[3])
        logger.debug('Matched strings kv: {} equals {}'.format(key, value))
        self._add_element(ElementTypes.STRINGS_KEY_VALUE, (key, value, ))

    def p_string_modifers(self, p):
        '''string_modifiers : string_modifiers string_modifier
                            | string_modifier'''

    def p_string_modifier(self, p):
        '''string_modifier : NOCASE
                           | ASCII
                           | WIDE
                           | FULLWORD'''
        logger.debug('Matched a string modifier: {}'.format(p[1]))
        self._add_element(ElementTypes.STRINGS_MODIFIER, p[1])

    def p_comments(self, p):
        '''comments : COMMENT
                    | MCOMMENT'''
        logger.debug("Matched a comment: {}".format(p[1]))

    # Condition elements.
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
                | XOR
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
                | STRINGCOUNT
                | REXSTRING'''

        logger.debug('Matched a condition term: {}'.format(p[1]))
        self._add_element(ElementTypes.TERM, p[1])

    # Error rule for syntax errors
    def p_error(self, p):
        raise TypeError('Unknown text at {} ; token of type {}'.format(p.value, p.type))


def main():
    """Run main function."""
    parser = argparse.ArgumentParser(description='Parse Yara rules into a dictionary representation.')
    parser.add_argument('file', metavar='FILE', help='File containing YARA rules to parse.')
    parser.add_argument('--log', help='Enable debug logging to the console.', action='store_true')
    args, _ = parser.parse_known_args()

    with open(args.file, 'r') as fh:
        input_string = fh.read()

    plyara = Plyara(console_logging=args.log)
    rules = plyara.parse_string(input_string)
    print(json.dumps(rules, sort_keys=True, indent=4))


if __name__ == '__main__':
    main()
