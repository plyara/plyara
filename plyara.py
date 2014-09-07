__author__ = 'christianbuia'
import ply.lex as lex
import sys
import json

def build_lexer():

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
       'PERIOD',
       'COLON',
       'COMMENT',
       'NEWLINE',
       'STAR',
       'HYPHEN',
       'AMPERSAND'
    ]

    reserved = {
       'and': 'AND',
       'at': 'AT',
       'in': 'IN',
       'or': 'OR',
       'rule': 'RULE',
       'wide': 'WIDE',
       'nocase': 'NOCASE',
       'import': 'IMPORT'
    }

    tokens = tokens + list(reserved.values())



    def t_COMMENT(t):
        r'(//.*)(?=\n)'
        pass
        # No return value. Token discarded

    #http://comments.gmane.org/gmane.comp.python.ply/134
    def t_MCOMMENT(t):
        r'/\*(.|\n)*?\*/'
        t.lineno += t.value.count('\n')
        pass

    def t_SECTIONMETA(t):
        r'meta:'
        t.value = t.value
        return t

    def t_SECTIONSTRINGS(t):
        r'strings:'
        t.value = t.value
        return t

    def t_SECTIONCONDITION(t):
        r'condition:'
        t.value = t.value
        return t

    def t_STRING(t):
        r'".+"'
        t.value = t.value
        return t

    def t_BYTESTRING(t):
        r'\{[\|\(\)\[\]\-\?a-fA-f0-9\s]+\}'
        t.value = t.value
        return t

    def t_REXSTRING(t):
        r'\/.+\/(?=\s|$)'
        t.value = t.value
        return t

    def t_STRINGNAME(t):
        r'\$[0-9a-zA-Z\-_]*'
        t.value = t.value
        return t

    def t_STRINGNAME_ARRAY(t):
        r'@[0-9a-zA-Z\-_]*'
        t.value = t.value
        return t

    def t_ID(t):
        r'[a-zA-Z_0-9]+'
        t.type = reserved.get(t.value,'ID')    # Check for reserved words
        return t

    def t_STRINGCOUNT(t):
        r'\#[^\s]*'
        t.value = t.value
        return t

    # Define a rule so we can track line numbers
    def t_NEWLINE(t):
        r'\n+'
        t.lexer.lineno += len(t.value)
        t.value = t.value
        return t

    # A string containing ignored characters (spaces and tabs)
    t_ignore  = ' \t'

    # Error handling rule
    def t_error(t):
        print("Illegal character '%s'" % t.value[0])
        t.lexer.skip(1)

    # Regular expression rules for simple tokens
    t_LPAREN  = r'\('
    t_RPAREN  = r'\)'
    t_EQUALS = r'='
    t_LBRACE = r'{'
    t_RBRACE = r'}'
    t_PLUS = r'\+'
    t_PIPE = r'\|'
    t_BACKSLASH = r'\\'
    t_FORWARDSLASH = r'/'
    t_COMMA = r','
    t_GREATERTHAN = r'>'
    t_LESSTHAN = r'<'
    t_PERIOD = r'\.'
    t_COLON = r':'
    t_STAR = r'\*'
    t_LBRACK = r'\['
    t_RBRACK = r'\]'
    t_HYPHEN = r'\-'
    t_AMPERSAND = r'&'


    # Build the lexer
    lexer = lex.lex()
    return lexer, tokens

#------------------------------------

def return_all_tokens(f_name):
    lexer, tokens = build_lexer()

    file_contents = open(f_name, "r").read()

    lex.input(file_contents)

    all_tokens = []

    while True:
        tok = lex.token()
        if tok is None:
            break
        if "Illegal" in tok.type:
            sys.stderr.write("error..." + tok.type + "\n")
            sys.stderr.write("exiting...\n")
            exit(1)
        all_tokens.append({"type": tok.type, "value": tok.value})

    return all_tokens

#------------------------------------
def extract_rules(all_tokens):

    #Rules list to contain all dictionaries that describe a Yara rule.
    rules = []

    while len(all_tokens) > 0:
        token = all_tokens.pop(0)
        if token["type"] == "RULE":
            #we have a 'rule' token...next should be the rule name
            token = all_tokens.pop(0)
            if token["type"] != "ID":
                sys.stderr.write("expected an ID token for rulename...syntax error? exiting.\n")
                exit(1)
            else:
                #=====================================================
                #====================================RULE CREATION
                rule = {}
                rule["name"] = token["value"]
                #sys.stderr.write("working on rule " + rule["name"] + "\n")
                token = all_tokens.pop(0)
                #------------------------------------START TAGS
                tags = []
                if token["type"] == "COLON":
                    while True:
                        token = all_tokens.pop(0)
                        if token["type"] == "RBRACE" or token["type"] == "NEWLINE":
                            break
                        if token["type"] == "ID":
                            tags.append(token["value"])
                if len(tags) > 0:
                    rule["tags"] = tags
                #------------------------------------END TAGS

                #pop the LBRACE or the NEWLINEs (they can come in any order) until SECTIONMETA
                meta_exists = True
                strings_exists = True
                while True:
                    token = all_tokens.pop(0)

                    if token["type"] == "SECTIONSTRINGS" or token["type"] == "SECTIONCONDITION":
                        #no meta in this rule
                        meta_exists = False
                        break

                    if token["type"] == "SECTIONMETA":
                        break

                #------------------------------------META:
                if meta_exists == True:
                    meta = []
                    #Now cycle through the "meta:" section, harvesting meta
                    while True:
                        token = all_tokens.pop(0)
                        if token["type"] == "SECTIONSTRINGS":
                            break

                        if token["type"] == "SECTIONCONDITION":
                            strings_exists = False
                            break

                        #cycle through a line
                        while True:
                            if token["type"] == "NEWLINE":
                                break


                            if token["type"] != "ID":
                                sys.stderr.write("while parsing meta, expected an ID type for the left side.  exiting\n")
                                sys.stderr.write("received " + token["type"] + "\n")
                                sys.stderr.write(str(rule))
                                exit(1)
                            meta_left = token["value"]

                            token = all_tokens.pop(0)
                            if token["type"] != "EQUALS":
                                sys.stderr.write("while parsing meta, expected an EQUALS type for the equals token.exiting\n")
                                sys.stderr.write(str(rule))
                                exit(1)

                            token = all_tokens.pop(0)
                            if token["type"] != "STRING" and token["type"] != "ID":
                                sys.stderr.write("while parsing meta, expected a STRING type for the right side.  exiting\n")
                                sys.stderr.write("received " + token["type"] + "\n")
                                sys.stderr.write(str(rule))
                                exit(1)
                            meta_right = token

                            meta.append({meta_left: meta_right})
                            token = all_tokens.pop(0)
                    if len(meta) > 0:
                        rule["meta"] = meta
                #------------------------------------END META:
                #~~~~~~~~~~~
                #~~~~~~~~~~~
                #------------------------------------STRINGS:
                if strings_exists == True:
                    strings = []
                    #Now cycle through the "strings:" section, harvesting strings
                    while True:
                        if token["type"] != "SECTIONCONDITION":
                            token = all_tokens.pop(0)

                        if token["type"] == "SECTIONCONDITION":
                            break

                        #cycle through a line
                        while True:
                            if token["type"] == "NEWLINE" or token["type"] == "SECTIONCONDITION":
                                break

                            if token["type"] != "STRINGNAME":
                                sys.stderr.write("while parsing strings, expected an STRINGNAME type for the left side.  exiting\n")
                                sys.stderr.write("received " + token["type"] + " " + token["value"] + "\n")
                                sys.stderr.write("current strings: " + json.dumps(strings) + "\n")
                                sys.stderr.write(str(rule))
                                exit(1)
                            string_left = token["value"]

                            token = all_tokens.pop(0)
                            if token["type"] != "EQUALS":
                                sys.stderr.write("while parsing strings, expected an EQUALS type for the equals token.exiting\n")
                                sys.stderr.write("received " + token["type"] + " " + token["value"] + "\n")
                                sys.stderr.write("current strings: " + json.dumps(strings) + "\n")
                                sys.stderr.write(str(rule))
                                exit(1)

                            token = all_tokens.pop(0)
                            if token["type"] not in ["STRING", "BYTESTRING","REXSTRING"]:
                                sys.stderr.write("while parsing strings, expected a STRING type for the right side.  exiting\n")
                                sys.stderr.write("received " + token["type"] + "\n")
                                sys.stderr.write(str(rule))
                                exit(1)
                            string_right = token

                            modifiers = []
                            while True:
                                token = all_tokens.pop(0)
                                if token["type"] == "SECTIONCONDITION":
                                    break

                                if token["type"] != "NEWLINE":
                                    modifiers.append(token["value"])
                                else:
                                    break

                            string_to_append = {string_left: string_right}
                            if len(modifiers) > 0:
                                string_to_append["modifiers"] = modifiers

                            strings.append(string_to_append)

                    if len(strings) > 0:
                        rule["strings"] = strings

                #------------------------------------END STRINGS:
                #~~~~~~~~~~~
                #~~~~~~~~~~~
                #------------------------------------CONDITIONS:

                conditions = []
                #Now cycle through the "conditions:" section

                while True:
                    if token["type"] != "RBRACE":
                        token = all_tokens.pop(0)
                    if token["type"] == "RBRACE":
                        break

                    #cycle through a line
                    condition = []
                    while True:
                        if (token["type"] == "NEWLINE" or token["type"] == "RBRACE") and condition != []:
                            conditions.append(condition)
                            condition = []
                            break
                        else:
                            if token["type"] != "NEWLINE":
                                condition.append(token["value"])
                            token = all_tokens.pop(0)

                if len(conditions) > 0:
                    rule["conditions"] = conditions

                #------------------------------------END CONDITIONS:


                rules.append(rule)
                #====================================END RULE CREATION
                #=====================================================
        #end top while

    return rules

def dictionaryFromRulesFile(file_name):
    dictRules = extract_rules(return_all_tokens(file_name))
    return dictRules

#------------------------------------
if __name__ == "__main__":

    if len(sys.argv) > 1:
        file_name = sys.argv[1]
        dictRules = dictionaryFromRulesFile(file_name)
        for rule in dictRules:
            print(json.dumps(rule) + "\n")
