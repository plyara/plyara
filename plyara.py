import argparse
import enum
import json
import logging
import codecs
import tempfile
import hashlib
import re

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
    COMMENT = 10
    MCOMMENT = 11


class Parser(object):
    """Interpret the output of the parser and produce an alternative representation of YARA rules."""

    COMPARISON_OPERATORS = ('==', '!=', '>', '<', '>=', '<=')

    IMPORT_OPTIONS = ('pe',
                      'elf',
                      'cuckoo',
                      'magic',
                      'hash',
                      'math',
                      'dotnet',
                      'androguard')

    KEYWORDS = ('all', 'and', 'any', 'ascii', 'at', 'condition',
                'contains', 'entrypoint', 'false', 'filesize',
                'fullword', 'for', 'global', 'in', 'import',
                'include', 'int8', 'int16', 'int32', 'int8be',
                'int16be', 'int32be', 'matches', 'meta', 'nocase',
                'not', 'or', 'of', 'private', 'rule', 'strings',
                'them', 'true', 'uint8', 'uint16', 'uint32', 'uint8be',
                'uint16be', 'uint32be', 'wide')

    FUNCTION_KEYWORDS = ('uint8', 'uint16', 'uint32', 'uint8be', 'uint16be', 'uint32be')


    def __init__(self, console_logging=False, store_raw_sections=True):
        """Initialize the parser object.

            Args:
                console_logging: enable a stream handler if no handlers exist (default False)
                store_raw_sections: enable attribute storage of raw section input
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
        """Set the console logger only if handler(s) aren't already set"""
        if not len(logger.handlers):
            logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            logger.addHandler(ch)

    def _add_element(self, element_type, element_value):
        """Accept elements from the parser and uses them to construct a representation of the YARA rule."""
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
            logger.debug(u'Adding Rule: {}'.format(self.current_rule['rule_name']))
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
        """Take a string input expected to consist of YARA rules, and return list of dictionaries representing them."""
        self.raw_input = input_string
        yacc.parse(input_string)

        for rule in self.rules:
            if any(self.imports):
                rule['imports'] = self.imports
            if any(self.includes):
                rule['includes'] = self.includes

        return self.rules

    @staticmethod
    def is_valid_rule_name(entry):
        """Checks to see if entry is a valid rule name."""
        # Check if entry is blank
        if not entry:
            return False

        # Check length
        if len(entry) > 128:
            return False

        # Ensure doesn't start with a digit
        if entry[0].isdigit():
            return False

        # Accept only alphanumeric and underscores
        if not re.match(r'\w+$', entry):
            return False

        # Verify not in keywords
        if entry in Parser.KEYWORDS:
            return False

        return True

    @staticmethod
    def is_valid_rule_tag(entry):
        """Checks to see if entry is a valid rule tag."""
        # Same lexical conventions as name
        return Parser.is_valid_rule_name(entry)

    @staticmethod
    def detect_imports(rule):
        """Takes a parsed yararule and provide a list of required imports based on condition."""
        detected_imports = []
        condition_terms = rule['condition_terms']

        for imp in Parser.IMPORT_OPTIONS:
            imp_string = u"\"{}\"".format(imp)
            imp_module = u"{}.".format(imp)

            if imp in condition_terms and imp_string not in detected_imports:
                detected_imports.append(imp_string)

            elif imp_string not in detected_imports:
                for term in condition_terms:
                    if term.startswith(imp_module):
                        detected_imports.append(imp_string)
                        break

        return detected_imports

    @staticmethod
    def detect_dependencies(rule):
        """Takes a parsed yararule and provide a list of external rule dependencies."""
        dependencies = []
        string_iteration_variables = []
        condition_terms = rule['condition_terms']

        # Number of terms for index iteration and reference
        term_count = len(condition_terms)

        for index in range(0, term_count):
            # Grab term by index
            term = condition_terms[index]

            if Parser.is_valid_rule_name(term) and (term not in Parser.IMPORT_OPTIONS):
                # Grab reference to previous term for logic checks
                if index > 0:
                    previous_term = condition_terms[index - 1]
                else:
                    previous_term = None

                # Grab reference to next term for logic checks
                if index < (term_count - 1):
                    next_term = condition_terms[index + 1]
                else:
                    next_term = None

                # Extend term indexes beyond wrapping parentheses for logic checks
                if previous_term == '(' and next_term == ')':
                    if (index - 2) >= 0:
                        previous_term = condition_terms[index - 2]
                    else:
                        previous_term = None

                    if (index + 2) < term_count:
                        next_term = condition_terms[index + 2]
                    else:
                        next_term = None

                # Check if reference is a variable for string iteration
                if term in string_iteration_variables:
                    continue

                if previous_term in ('any', 'all') and next_term == 'in':
                    string_iteration_variables.append(term)
                    continue

                # Check for external string variable dependency
                if ((next_term in ('matches', 'contains')) or (previous_term in ('matches', 'contains'))):
                    continue

                # Check for external integer variable dependency
                if ((next_term in Parser.COMPARISON_OPERATORS) or (previous_term in Parser.COMPARISON_OPERATORS)):
                    continue

                # Check for external boolean dependency may not be possible without stripping out valid rule references

                # Checks for likely rule reference
                if previous_term is None and next_term is None:
                    dependencies.append(term)
                elif previous_term in ('and', 'or') or next_term in ('and', 'or'):
                    dependencies.append(term)

        return dependencies

    @staticmethod
    def generate_logic_hash(rule):
        """Calculate hash value of rule strings and condition."""
        strings = rule.get('strings', [])
        conditions = rule['condition_terms']

        string_values = []
        condition_mapping = []
        string_mapping = {'anonymous': [], 'named': {}}

        for entry in strings:
            name = entry['name']
            modifiers = entry.get('modifiers', [])

            # Handle string modifiers
            if modifiers:
                value = entry['value'] + u'<MODIFIED>' + u' & '.join(sorted(modifiers))
            else:
                value = entry['value']

            if name == '$':
                # Track anonymous strings
                string_mapping['anonymous'].append(value)
            else:
                # Track named strings
                string_mapping['named'][name] = value

            # Track all string values
            string_values.append(value)

        # Sort all string values
        sorted_string_values = sorted(string_values)

        for condition in conditions:
            # All string references (sort for consistency)
            if condition == 'them' or condition == '$*':
                condition_mapping.append(u'<STRINGVALUE>' + u' | '.join(sorted_string_values))

            elif condition.startswith('$') and condition != '$':
                # Exact Match
                if condition in string_mapping['named']:
                    condition_mapping.append(u'<STRINGVALUE>' + string_mapping['named'][condition])
                # Wildcard Match
                elif '*' in condition:
                    wildcard_strings = []
                    condition = condition.replace('$', '\$').replace('*', '.*')
                    pattern = re.compile(condition)

                    for name, value in string_mapping['named'].items():
                        if pattern.match(name):
                            wildcard_strings.append(value)

                    wildcard_strings.sort()
                    condition_mapping.append(u'<STRINGVALUE>' + u' | '.join(wildcard_strings))
                else:
                    logger.error(u'[!] Unhandled String Condition {}'.format(condition))

            # Count Match
            elif condition.startswith('#') and condition != '#':
                condition = condition.replace('#', '$')

                if condition in string_mapping['named']:
                    condition_mapping.append('<COUNTOFSTRING>' + string_mapping['named'][condition])
                else:
                    logger.error(u'[!] Unhandled String Count Condition {}'.format(condition))

            else:
                condition_mapping.append(condition)

        logic_hash = hashlib.sha1(u''.join(condition_mapping).encode()).hexdigest()
        return logic_hash

    @staticmethod
    def rebuild_yara_rule(rule):
        """Take a parsed yararule and rebuild it into a usable one."""

        rule_format = u"{imports}{scopes}rule {rulename}{tags} {{\n{meta}{strings}{condition}\n}}\n"

        rule_name = rule['rule_name']

        # Rule Imports
        if rule.get('imports'):
            unpacked_imports = [u'import "{}"\n'.format(entry) for entry in rule['imports']]
            rule_imports = u'{}\n'.format(u''.join(unpacked_imports))
        else:
            rule_imports = u''

        # Rule Scopes
        if rule.get('scopes'):
            rule_scopes = u'{} '.format(u' '.join(rule['scopes']))
        else:
            rule_scopes = u''

        # Rule Tags
        if rule.get('tags'):
            rule_tags = u' : {}'.format(u' '.join(rule['tags']))
        else:
            rule_tags = u''

        # Rule Metadata
        if rule.get('metadata'):
            unpacked_meta = [u'\n\t\t{key} = {value}'.format(key=k, value=v)
                             for k, v in rule['metadata'].items()]
            rule_meta = u'\n\tmeta:{}\n'.format(u''.join(unpacked_meta))
        else:
            rule_meta = u''

        # Rule Strings
        if rule.get('strings'):

            string_container = []

            for rule_string in rule['strings']:

                if 'modifiers' in rule_string:
                    string_modifiers = u' '.join(rule_string['modifiers'])

                    fstring = u'\n\t\t{} = {} {}'.format(rule_string['name'],
                                                         rule_string['value'],
                                                         string_modifiers)
                else:
                    fstring = u'\n\t\t{} = {}'.format(rule_string['name'],
                                                      rule_string['value'])

                string_container.append(fstring)

            rule_strings = u'\n\tstrings:{}\n'.format(u''.join(string_container))
        else:
            rule_strings = u''

        if rule.get('condition_terms'):
            # Format condition with appropriate whitespace between keywords
            cond = []

            for term in rule['condition_terms']:

                if not cond:

                    if term in Parser.FUNCTION_KEYWORDS:
                        cond.append(term)

                    elif term in Parser.KEYWORDS:
                        cond.append(term)
                        cond.append(u' ')

                    else:
                        cond.append(term)

                else:

                    if cond[-1] == ' ' and term in Parser.FUNCTION_KEYWORDS:
                        cond.append(term)

                    elif cond and cond[-1] != ' ' and term in Parser.FUNCTION_KEYWORDS:
                        cond.append(u' ')
                        cond.append(term)

                    elif cond[-1] == ' ' and term in Parser.KEYWORDS:
                        cond.append(term)
                        cond.append(u' ')

                    elif cond and cond[-1] != ' ' and term in Parser.KEYWORDS:
                        cond.append(u' ')
                        cond.append(term)
                        cond.append(u' ')

                    else:
                        cond.append(term)

            fcondition = u''.join(cond).rstrip(' ')
            rule_condition = u'\n\tcondition:\n\t\t{}'.format(fcondition)
        else:
            rule_condition = u''

        formatted_rule = rule_format.format(imports=rule_imports,
                                            rulename=rule_name,
                                            tags=rule_tags,
                                            meta=rule_meta,
                                            scopes=rule_scopes,
                                            strings=rule_strings,
                                            condition=rule_condition)

        return formatted_rule

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
        'TILDE',
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
    t_TILDE = r'~'
    t_XOR = r'\^'
    t_PERIOD = r'\.'
    t_COLON = r':'
    t_STAR = r'\*'
    t_LBRACK = r'\['
    t_RBRACK = r'\]'
    t_HYPHEN = r'\-'
    t_AMPERSAND = r'&'
    t_DOTDOT = r'\.\.'

    states = (
        ('STRING','exclusive'),
        ('BYTESTRING','exclusive'),
    )

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

    # http://comments.gmane.org/gmane.comp.python.ply/134
    def t_MCOMMENT(self, t):
        # r'/\*(.|\n)*?\*/'
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

    def t_begin_STRING(self, t):
        r'"'
        t.lexer.escape = 0
        t.lexer.string_start = t.lexer.lexpos - 1
        t.lexer.begin('STRING')

    def t_STRING_value(self, t):
        r'.'
        if t.lexer.escape == 0 and t.value == '"':
            t.type = "STRING"
            t.value = t.lexer.lexdata[t.lexer.string_start : t.lexer.lexpos]
            t.lexer.begin('INITIAL')
            return t

        if t.value == '\\' or t.lexer.escape == 1:
            t.lexer.escape ^= 1

    t_STRING_ignore = ' \t\n'

    def t_STRING_error(self, t):
        raise TypeError("Illegal string character " + t.value[0] + " at line " + str(t.lexer.lineno))

    def t_begin_BYTESTRING(self, t):
        r'\{'

        if hasattr(t.lexer, 'section') and t.lexer.section == 'strings':
            t.lexer.bytestring_start = t.lexer.lexpos - 1
            t.lexer.begin('BYTESTRING')
        else:
            t.type = "LBRACE"
            return t

    def t_BYTESTRING_pair(self, t):
        r'\s*[a-fA-F0-9?]{2}\s*'

    def t_BYTESTRING_group(self, t):
        r'\((\s*[a-fA-F0-9?]{2}\s*\|?\s*|\s*\[\d*-?\d*\]\s*)+\)'

    def t_BYTESTRING_comment(self, t):
        r'\/\/[^\r\n]*'

    def t_BYTESTRING_mcomment(self, t):
        r'/\*(.|\n|\r\n)*?\*/'

    def t_BYTESTRING_jump(self, t):
        r'\[\s*(\d*)\s*-?\s*(\d*)\s*\]'
        lower_bound = t.lexer.lexmatch.group(8)
        upper_bound = t.lexer.lexmatch.group(9)

        if lower_bound and upper_bound:
            if not 0 <= int(lower_bound) <= int(upper_bound):
                raise ValueError("Illegal bytestring jump bounds " + t.value + " at line " + str(t.lexer.lineno))

    def t_BYTESTRING_end(self, t):
        r'\}'
        t.type = "BYTESTRING"
        t.value = t.lexer.lexdata[t.lexer.bytestring_start : t.lexer.lexpos]
        t.lexer.begin('INITIAL')
        return t

    t_BYTESTRING_ignore = ' \r\n\t'

    def t_BYTESTRING_error(self, t):
        raise TypeError("Illegal bytestring character " + t.value[0] + " at line " + str(t.lexer.lineno))

    def t_REXSTRING(self, t):
        r'''
        # Two parts to this regex, because I'm not sure how to simplify.

        (\/.+(?:\/[ismx]*)(?=\s+(?:nocase|ascii|wide|fullword)?\s*\/))  |  # first half matches `/abc123/im // comment` format
        (\/.+(?:\/[ismx]*)(?=\s|\)|$))                                     # second half matches `/abc123/im` format
        '''
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
        raise TypeError(u'Illegal character {} at line {}'.format(t.value[0], t.lexer.lineno))

    # Parsing rules

    precedence = (('right', 'NUM'), ('right', 'ID'), ('right', 'HEXNUM'))

    def p_rules(self, p):
        '''rules : rules rule
                 | rule'''

    def p_rule(self, p):
        '''rule : imports_and_scopes RULE ID tag_section LBRACE rule_body RBRACE'''

        logger.debug(u'Matched rule: {}'.format(p[3]))
        logger.debug(u'Rule start: {}, Rule stop: {}'.format(p.lineno(2), p.lineno(7)))

        while self._rule_comments:
            comment = self._rule_comments.pop()

            if p.lexpos(5) < comment.lexpos < p.lexpos(7):
                self._add_element(getattr(ElementTypes, comment.type), comment.value)

        element_value = (p[3], int(p.lineno(2)), int(p.lineno(7)), )
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
        import_value = p[2].replace('"', '')
        logger.debug(u'Matched import: {}'.format(import_value))
        self._add_element(ElementTypes.IMPORT, import_value)

    def p_include(self, p):
        'include : INCLUDE STRING'
        include_value = p[2].replace('"', '')
        logger.debug(u'Matched include: {}'.format(include_value))
        self._add_element(ElementTypes.INCLUDE, include_value)

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
        logger.debug(u'Matched tag: {}'.format(p[1]))
        self._add_element(ElementTypes.TAG, p[1])

    def p_scope(self, p):
        '''scope : PRIVATE
                 | GLOBAL'''
        logger.debug(u'Matched scope identifier: {}'.format(p[1]))
        self._add_element(ElementTypes.SCOPE, p[1])

    def p_rule_body(self, p):
        'rule_body : sections'
        logger.debug(u'Matched rule body')

    def p_rule_sections(self, p):
        '''sections : sections section
                    | section'''

    def p_rule_section(self, p):
        '''section : meta_section
                   | strings_section
                   | condition_section'''

    def p_meta_section(self, p):
        'meta_section : SECTIONMETA meta_kvs'
        logger.debug(u'Matched meta section')

    def p_strings_section(self, p):
        'strings_section : SECTIONSTRINGS strings_kvs'

    def p_condition_section(self, p):
        '''condition_section : SECTIONCONDITION expression'''

    # Meta elements.
    def p_meta_kvs(self, p):
        '''meta_kvs : meta_kvs meta_kv
                    | meta_kv'''
        logger.debug(u'Matched meta kvs')

    def p_meta_kv(self, p):
        '''meta_kv : ID EQUALS STRING
                   | ID EQUALS ID
                   | ID EQUALS TRUE
                   | ID EQUALS FALSE
                   | ID EQUALS NUM'''
        key = p[1]
        value = p[3].strip('"')
        logger.debug(u'Matched meta kv: {} equals {}'.format(key, value))
        self._add_element(ElementTypes.METADATA_KEY_VALUE, (key, value, ))

    # Strings elements.
    def p_strings_kvs(self, p):
        '''strings_kvs : strings_kvs strings_kv
                       | strings_kv'''
        logger.debug(u'Matched strings kvs')

    def p_strings_kv(self, p):
        '''strings_kv : STRINGNAME EQUALS STRING
                      | STRINGNAME EQUALS STRING string_modifiers
                      | STRINGNAME EQUALS BYTESTRING
                      | STRINGNAME EQUALS REXSTRING
                      | STRINGNAME EQUALS REXSTRING comments
                      | STRINGNAME EQUALS REXSTRING string_modifiers
                      | STRINGNAME EQUALS REXSTRING string_modifiers comments'''

        key = p[1]
        value = p[3]
        logger.debug(u'Matched strings kv: {} equals {}'.format(key, value))
        self._add_element(ElementTypes.STRINGS_KEY_VALUE, (key, value, ))

    def p_string_modifers(self, p):
        '''string_modifiers : string_modifiers string_modifier
                            | string_modifier'''

    def p_string_modifier(self, p):
        '''string_modifier : NOCASE
                           | ASCII
                           | WIDE
                           | FULLWORD'''
        logger.debug(u'Matched a string modifier: {}'.format(p[1]))
        self._add_element(ElementTypes.STRINGS_MODIFIER, p[1])

    def p_comments(self, p):
        '''comments : COMMENT
                    | MCOMMENT'''
        logger.debug(u'Matched a comment: {}'.format(p[1]))

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
                | TILDE
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

        logger.debug(u'Matched a condition term: {}'.format(p[1]))
        self._add_element(ElementTypes.TERM, p[1])

    # Error rule for syntax errors
    def p_error(self, p):
        if not p:
            # This happens when we try to parse an empty string or file, or one with no actual rules.
            pass
        elif p.type in ('COMMENT', 'MCOMMENT'):
            # Just a comment - tell parser that it is okay
            self.parser.errok()
            self._rule_comments.append(p)
        else:
            raise TypeError(u'Unknown text {} for token of type {} on line {}'.format(p.value, p.type, p.lineno))


def main():
    """Run main function."""
    parser = argparse.ArgumentParser(description='Parse YARA rules into a dictionary representation.')
    parser.add_argument('file', metavar='FILE', help='File containing YARA rules to parse.')
    parser.add_argument('--log', help='Enable debug logging to the console.', action='store_true')
    args, _ = parser.parse_known_args()

    with codecs.open(args.file, 'r', encoding='utf-8') as fh:
        input_string = fh.read()

    plyara = Plyara(console_logging=args.log)
    rules = plyara.parse_string(input_string)

    # can't JSON-serialize sets, so convert them to lists at print time
    def default(obj):
        if isinstance(obj, set):
            return list(obj)
        raise TypeError

    print(json.dumps(rules, sort_keys=True, indent=4, default=default))


if __name__ == '__main__':
    main()
